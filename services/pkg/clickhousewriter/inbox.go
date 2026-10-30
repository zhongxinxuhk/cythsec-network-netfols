package clickhousewriter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// InboxConfig consumes only immutable, atomically published top-level *.jsonl files.
// Queue.Directory is an exclusive state root; each filename has its own resumable queue.
type InboxConfig struct {
	Directory    string
	Queue        Config
	BatchRows    int
	BatchBytes   int
	MaxSources   int // Bounds both directory entries per scan and retained source states.
	PollInterval time.Duration
	OnComplete   func(name string, stats Stats)
}

type InboxStats struct {
	KnownSources     int    `json:"known_sources"`
	CompletedSources int    `json:"completed_sources"`
	DeliveredRows    uint64 `json:"delivered_rows"`
	RecoveredRows    uint64 `json:"recovered_rows"`
	ActiveSource     string `json:"active_source,omitempty"`
	ActiveStats      *Stats `json:"active_stats,omitempty"`
}

type inboxBinding struct {
	Version   int    `json:"version"`
	Directory string `json:"directory"`
	Target    string `json:"target"`
	Checksum  string `json:"checksum"`
}

// Inbox serializes files, so MaxPendingBytes remains a global payload bound.
// Completed files and their checkpoints are retained. Retention is an operator action.
type Inbox struct {
	cfg          InboxConfig
	lock         *os.File
	states       map[string]bool
	completed    map[string]os.FileInfo
	mu           sync.Mutex
	busy, closed bool
	stats        InboxStats
}

func sourceKey(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

func containsPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// Filesystem identity also catches case aliases on case-insensitive volumes.
func ancestorIdentity(info os.FileInfo, path string) (bool, error) {
	for {
		current, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		if os.SameFile(info, current) {
			return true, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return false, nil
		}
		path = parent
	}
}

func boundedEntries(directory string, limit int) ([]os.DirEntry, error) {
	f, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, fmt.Errorf("目录条目超过上限 %d，拒绝截断扫描", limit)
	}
	return entries, nil
}

func OpenInbox(cfg InboxConfig) (_ *Inbox, err error) {
	if cfg.Directory == "" || cfg.Queue.Directory == "" || cfg.Queue.Target == "" || cfg.Queue.MaxPendingBytes <= 0 || cfg.Queue.RetryInterval <= 0 || cfg.Queue.MaxAttempts <= 0 || cfg.BatchRows <= 0 || cfg.BatchBytes <= 1 || cfg.MaxSources <= 0 || cfg.MaxSources > 100000 || cfg.PollInterval <= 0 {
		return nil, errors.New("输入目录、队列、批次、重试、扫描间隔与文件上限必须有效（上限不超过100000）")
	}
	cfg.Directory, err = filepath.EvalSymlinks(cfg.Directory)
	if err != nil {
		return nil, err
	}
	cfg.Directory, err = filepath.Abs(cfg.Directory)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(cfg.Directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("输入必须是已存在的目录")
	}
	spool, err := filepath.Abs(cfg.Queue.Directory)
	if err != nil {
		return nil, err
	}
	if containsPath(cfg.Directory, spool) || containsPath(spool, cfg.Directory) {
		return nil, errors.New("输入目录与状态目录必须相互独立")
	}
	if info, e := os.Lstat(spool); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("状态根目录不能是符号链接")
	}
	// Persist newly created directory entries before writing the inbox binding.
	var created []string
	for p := spool; ; p = filepath.Dir(p) {
		if _, e := os.Stat(p); e == nil {
			break
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		created = append(created, p)
	}
	if err = os.MkdirAll(spool, 0700); err != nil {
		return nil, err
	}
	for _, p := range created {
		if err = syncDirectory(filepath.Dir(p)); err != nil {
			return nil, err
		}
	}
	spool, err = filepath.EvalSymlinks(spool)
	if err != nil {
		return nil, err
	}
	if containsPath(cfg.Directory, spool) || containsPath(spool, cfg.Directory) {
		return nil, errors.New("输入目录与状态目录解析后重叠")
	}
	spoolInfo, err := os.Stat(spool)
	if err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		info os.FileInfo
		path string
	}{{info, spool}, {spoolInfo, cfg.Directory}} {
		overlap, e := ancestorIdentity(pair.info, pair.path)
		if e != nil {
			return nil, e
		}
		if overlap {
			return nil, errors.New("输入目录与状态目录在文件系统上重叠")
		}
	}
	cfg.Queue.Directory = spool
	lock, err := os.OpenFile(filepath.Join(spool, ".inbox.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("目录消费者已被其他进程占用: %w", err)
	}
	defer func() {
		if err != nil {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
		}
	}()
	inbox := &Inbox{cfg: cfg, lock: lock, states: make(map[string]bool), completed: make(map[string]os.FileInfo)}
	entries, err := boundedEntries(spool, cfg.MaxSources+2)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() == ".inbox.lock" || entry.Name() == ".inbox" {
			if !entry.Type().IsRegular() {
				return nil, errors.New("目录绑定与锁必须是普通文件")
			}
			continue
		}
		key, e := hex.DecodeString(entry.Name())
		if e != nil || len(key) != 32 || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("状态目录含未知或未提交条目，需检查后恢复")
		}
		inbox.states[entry.Name()] = true
	}
	if len(inbox.states) > cfg.MaxSources {
		return nil, errors.New("已有源文件状态超过上限")
	}
	file := filepath.Join(spool, ".inbox")
	data, readErr := os.ReadFile(file)
	if readErr == nil {
		var stored inboxBinding
		if json.Unmarshal(data, &stored) != nil {
			return nil, errors.New("目录绑定损坏")
		}
		want := stored.Checksum
		stored.Checksum = ""
		if stored.Version != 1 || want != checksum(stored) || stored.Directory != cfg.Directory || stored.Target != cfg.Queue.Target {
			return nil, errors.New("目录绑定校验失败，禁止改投目标或更换输入目录")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	} else {
		if len(inbox.states) != 0 {
			return nil, errors.New("源队列存在但目录绑定缺失")
		}
		binding := inboxBinding{Version: 1, Directory: cfg.Directory, Target: cfg.Queue.Target}
		binding.Checksum = checksum(binding)
		data, _ := json.Marshal(binding)
		if err = atomicWrite(spool, ".inbox", data); err != nil {
			return nil, err
		}
	}
	inbox.stats.KnownSources = len(inbox.states)
	return inbox, nil
}

func (in *Inbox) begin() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed || in.busy {
		return errors.New("目录消费者已关闭或正在运行")
	}
	in.busy = true
	return nil
}
func (in *Inbox) end() { in.mu.Lock(); in.busy = false; in.mu.Unlock() }

func (in *Inbox) Scan(ctx context.Context, send func(context.Context, string, []byte) error) error {
	if err := in.begin(); err != nil {
		return err
	}
	defer in.end()
	return in.scan(ctx, send)
}

func (in *Inbox) Run(ctx context.Context, send func(context.Context, string, []byte) error) error {
	if err := in.begin(); err != nil {
		return err
	}
	defer in.end()
	for {
		if err := in.scan(ctx, send); err != nil {
			return err
		}
		timer := time.NewTimer(in.cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (in *Inbox) scan(ctx context.Context, send func(context.Context, string, []byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if send == nil {
		return errors.New("发送函数不能为空")
	}
	entries, err := boundedEntries(in.cfg.Directory, in.cfg.MaxSources)
	if err != nil {
		return err
	}
	files := make(map[string]os.FileInfo)
	keys := make(map[string]bool)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("已发布源 %q 不是普通文件", entry.Name())
		}
		files[entry.Name()] = info
		keys[sourceKey(entry.Name())] = true
	}
	for key := range in.states {
		if !keys[key] {
			return errors.New("已登记源文件缺失，拒绝跳过持久化状态")
		}
	}
	newSources := len(in.states)
	var names []string
	for name := range files {
		names = append(names, name)
		if !in.states[sourceKey(name)] {
			newSources++
		}
	}
	if newSources > in.cfg.MaxSources {
		return errors.New("源文件累计状态超过上限")
	}
	// Recover registered files before accepting new publications.
	sort.Slice(names, func(i, j int) bool {
		a, b := in.states[sourceKey(names[i])], in.states[sourceKey(names[j])]
		if a != b {
			return a
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		info := files[name]
		if old := in.completed[name]; old != nil && os.SameFile(old, info) && old.Size() == info.Size() && old.ModTime().Equal(info.ModTime()) {
			continue
		}
		in.mu.Lock()
		in.stats.ActiveSource = name
		in.mu.Unlock()
		stats, e := in.consume(ctx, name, info, send)
		in.mu.Lock()
		in.stats.DeliveredRows += stats.DeliveredRows
		in.stats.RecoveredRows += stats.RecoveredRows
		in.stats.ActiveStats = &stats
		in.mu.Unlock()
		if e != nil {
			return fmt.Errorf("源文件 %q 未完成: %w", name, e)
		}
		in.states[sourceKey(name)] = true
		if in.completed[name] == nil {
			in.mu.Lock()
			in.stats.CompletedSources++
			in.mu.Unlock()
		}
		in.completed[name] = info
		in.mu.Lock()
		in.stats.KnownSources = len(in.states)
		in.stats.ActiveSource = ""
		in.stats.ActiveStats = nil
		in.mu.Unlock()
		if in.cfg.OnComplete != nil {
			in.cfg.OnComplete(name, stats)
		}
	}
	return nil
}

func (in *Inbox) consume(ctx context.Context, name string, expected os.FileInfo, send func(context.Context, string, []byte) error) (stats Stats, err error) {
	f, err := os.OpenFile(filepath.Join(in.cfg.Directory, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return stats, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return stats, err
	}
	if !actual.Mode().IsRegular() || !os.SameFile(expected, actual) {
		return stats, errors.New("源文件在扫描后被替换")
	}
	cfg := in.cfg.Queue
	cfg.Directory = filepath.Join(cfg.Directory, sourceKey(name))
	cfg.ResumeFile = true
	q, err := Open(cfg)
	if err != nil {
		return stats, err
	}
	in.states[sourceKey(name)] = true
	in.mu.Lock()
	in.stats.KnownSources = len(in.states)
	in.mu.Unlock()
	defer func() { stats = q.Stats(); err = errors.Join(err, q.Close()) }()
	if err = q.BindFile(f); err != nil {
		return stats, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { e := q.Run(workerCtx, send); done <- e; cancel() }()
	err = q.WaitEmpty(workerCtx)
	if err == nil {
		err = q.ConsumeFile(workerCtx, f, in.cfg.BatchRows, in.cfg.BatchBytes)
	}
	if err == nil {
		err = q.WaitEmpty(workerCtx)
	}
	cancel()
	workerErr := <-done
	if workerErr != nil && !errors.Is(workerErr, context.Canceled) {
		err = workerErr
	}
	return stats, err
}

func (in *Inbox) Stats() InboxStats {
	in.mu.Lock()
	defer in.mu.Unlock()
	stats := in.stats
	if stats.ActiveStats != nil {
		active := *stats.ActiveStats
		stats.ActiveStats = &active
	}
	return stats
}

func (in *Inbox) Close() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.busy {
		return errors.New("先停止目录消费者")
	}
	if in.closed {
		return nil
	}
	in.closed = true
	return errors.Join(syscall.Flock(int(in.lock.Fd()), syscall.LOCK_UN), in.lock.Close())
}
