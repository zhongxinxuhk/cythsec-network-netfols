// Package clickhousewriter 提供有界、先落盘再发送的批次队列。
// 接收确认是 Enqueue 成功；传输语义为 at-least-once，去重取决于目标表的窗口。
package clickhousewriter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Directory       string
	Target          string // 不含密码；同一目录不能改投另一个目标。
	MaxPendingBytes int64
	RetryInterval   time.Duration
	MaxAttempts     int
	ResumeFile      bool // 仅不可变文件模式可将未提交的 atomicWrite 临时文件留待检查并从源重读。
}

type Stats struct {
	AcceptedRows      uint64 `json:"accepted_rows"`
	RecoveredRows     uint64 `json:"recovered_rows"`
	DeliveredRows     uint64 `json:"delivered_rows"`
	PendingBatches    int    `json:"pending_batches"`
	PendingBytes      int64  `json:"pending_bytes"`
	Attempts          uint64 `json:"attempts"`
	Failures          uint64 `json:"failures"`
	BackpressureWaits uint64 `json:"backpressure_waits"`
	SourceOffset      int64  `json:"source_offset"`
	SourceRows        uint64 `json:"source_rows"`
	SourceSHA256      string `json:"source_sha256,omitempty"`
	SourceSize        int64  `json:"source_size,omitempty"`
	UncommittedTemps  int    `json:"uncommitted_temps,omitempty"`
}

type batch struct {
	Version int          `json:"version"`
	ID      string       `json:"id"`
	Rows    int          `json:"rows"`
	SHA256  string       `json:"sha256"`
	Data    []byte       `json:"data"`
	Source  *sourceRange `json:"source,omitempty"`
}

type Queue struct {
	cfg     Config
	lock    *os.File
	mu      sync.Mutex
	changed chan struct{}
	stats   Stats
	running bool
	closed  bool
	fatal   error
	source  *sourceState
}

// Open 锁住目录并校验已有批次；损坏或未完成文件不会被默默跳过。
func Open(cfg Config) (_ *Queue, err error) {
	if cfg.Directory == "" || cfg.Target == "" || cfg.MaxPendingBytes <= 0 || cfg.RetryInterval <= 0 || cfg.MaxAttempts <= 0 {
		return nil, errors.New("目录、目标、容量、重试间隔与尝试次数必须有效")
	}
	var created []string
	for path := filepath.Clean(cfg.Directory); ; path = filepath.Dir(path) {
		if _, statErr := os.Stat(path); statErr == nil {
			break
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		created = append(created, path)
	}
	if err = os.MkdirAll(cfg.Directory, 0700); err != nil {
		return nil, err
	}
	// 新目录本身也须在父目录中持久化，不能只同步批次所在目录。
	for _, path := range created {
		parent, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return nil, openErr
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil {
			return nil, syncErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	lock, err := os.OpenFile(filepath.Join(cfg.Directory, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("队列已被其他进程占用: %w", err)
	}
	defer func() {
		if err != nil {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
		}
	}()
	q := &Queue{cfg: cfg, lock: lock, changed: make(chan struct{})}
	if err = q.loadSource(); err != nil {
		return nil, err
	}
	meta := filepath.Join(cfg.Directory, ".target")
	stored, readErr := os.ReadFile(meta)
	if errors.Is(readErr, os.ErrNotExist) && q.source != nil {
		return nil, errors.New("源文件断点存在但目标绑定缺失")
	}
	if readErr == nil && string(stored) != cfg.Target {
		return nil, errors.New("队列目标与当前连接不一致，拒绝改投")
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	entries, err := os.ReadDir(cfg.Directory)
	if err != nil {
		return nil, err
	}
	var recovered []batch
	for _, e := range entries {
		if e.Name() == ".lock" || e.Name() == ".target" || e.Name() == ".source" {
			continue
		}
		if (cfg.ResumeFile || q.source != nil) && strings.HasPrefix(e.Name(), ".pending-") && strings.HasSuffix(e.Name(), ".tmp") && e.Type().IsRegular() {
			// rename 才是批次提交点；临时文件从未确认接收。文件模式保留证据并从已校验源重读。
			q.stats.UncommittedTemps++
			continue
		}
		if !strings.HasSuffix(e.Name(), ".batch") || e.Type()&os.ModeSymlink != 0 || e.IsDir() {
			return nil, fmt.Errorf("队列含未知/未完成文件 %s，需检查后恢复", e.Name())
		}
		if errors.Is(readErr, os.ErrNotExist) {
			return nil, errors.New("已有批次却缺少目标绑定文件")
		}
		info, statErr := e.Info()
		if statErr != nil {
			return nil, statErr
		}
		if info.Size() > cfg.MaxPendingBytes {
			return nil, errors.New("批次文件超过队列容量")
		}
		var existing batch
		if existing, err = q.read(e.Name()); err != nil {
			return nil, err
		}
		q.stats.RecoveredRows += uint64(existing.Rows)
		recovered = append(recovered, existing)
		q.stats.PendingBatches++
		q.stats.PendingBytes += info.Size()
	}
	if err = q.recoverSource(recovered); err != nil {
		return nil, err
	}
	if q.stats.PendingBytes > cfg.MaxPendingBytes {
		return nil, errors.New("已有队列超过配置容量，禁止缩小上限后启动")
	}
	if errors.Is(readErr, os.ErrNotExist) {
		if err = q.atomicWrite(".target", []byte(cfg.Target)); err != nil {
			return nil, err
		}
	}
	return q, nil
}

func (q *Queue) syncDirectory() error { return syncDirectory(q.cfg.Directory) }

func syncDirectory(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (q *Queue) atomicWrite(name string, data []byte) error {
	return atomicWrite(q.cfg.Directory, name, data)
}

func atomicWrite(directory, name string, data []byte) error {
	f, err := os.CreateTemp(directory, ".pending-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(directory, name)); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func rowCount(data []byte) (int, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return 0, errors.New("批次须为非空、换行结尾的 JSONL")
	}
	n := 0
	for _, line := range bytes.Split(data[:len(data)-1], []byte{'\n'}) {
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 || trim[0] != '{' || !json.Valid(trim) {
			return 0, errors.New("每行须为一个合法 JSON 对象")
		}
		n++
	}
	return n, nil
}

func (q *Queue) read(name string) (batch, error) {
	var b batch
	data, err := os.ReadFile(filepath.Join(q.cfg.Directory, name))
	if err != nil {
		return b, err
	}
	if err = json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("损坏的批次 %s: %w", name, err)
	}
	sum := sha256.Sum256(b.Data)
	n, validErr := rowCount(b.Data)
	if b.Version != 1 || b.ID+".batch" != name || b.Rows != n || validErr != nil || b.SHA256 != hex.EncodeToString(sum[:]) {
		return b, fmt.Errorf("批次 %s 的版本/ID/条数/SHA256 校验失败", name)
	}
	if err = q.validateRange(b); err != nil {
		return b, err
	}
	return b, nil
}

func (q *Queue) notify() { close(q.changed); q.changed = make(chan struct{}) }

// Enqueue 返回 nil 前同步文件和目录；容量不足时等待消费者释放空间。
func (q *Queue) Enqueue(ctx context.Context, data []byte) error {
	return q.enqueue(ctx, data, nil)
}

func (q *Queue) enqueue(ctx context.Context, data []byte, source *sourceRange) error {
	rows, err := rowCount(data)
	if err != nil {
		return err
	}
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	b := batch{Version: 1, ID: fmt.Sprintf("%020d-%x", time.Now().UnixNano(), idBytes), Rows: rows, SHA256: hex.EncodeToString(sum[:]), Data: data, Source: source}
	if source != nil {
		source.Checksum = rangeChecksum(*source, b.SHA256)
	}
	encoded, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > q.cfg.MaxPendingBytes {
		return errors.New("单批持久化字节已超过整个队列容量")
	}
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return errors.New("队列已关闭")
		}
		if q.fatal != nil {
			err := q.fatal
			q.mu.Unlock()
			return err
		}
		if err = ctx.Err(); err != nil {
			q.mu.Unlock()
			return err
		}
		if err = q.validateRange(b); err != nil {
			q.mu.Unlock()
			return err
		}
		if source != nil && source.Start != q.source.Offset {
			q.mu.Unlock()
			return errors.New("源文件偏移不连续")
		}
		if q.stats.PendingBytes+int64(len(encoded)) <= q.cfg.MaxPendingBytes {
			err = q.atomicWrite(b.ID+".batch", encoded)
			if err == nil && source != nil {
				next := *q.source
				next.Offset = source.End
				next.Rows += uint64(rows)
				err = q.saveSource(next)
			}
			if err == nil {
				q.stats.PendingBatches++
				q.stats.PendingBytes += int64(len(encoded))
				q.stats.AcceptedRows += uint64(rows)
			} else {
				q.fatal = err
			}
			q.notify()
			q.mu.Unlock()
			return err
		}
		q.stats.BackpressureWaits++
		changed := q.changed
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// Run 是唯一消费者，失败后保留原批次及稳定 token；取消不会删除正在发送的文件。
func (q *Queue) Run(ctx context.Context, send func(context.Context, string, []byte) error) error {
	q.mu.Lock()
	if q.closed || q.running {
		q.mu.Unlock()
		return errors.New("队列已关闭或消费者已启动")
	}
	q.running = true
	q.mu.Unlock()
	defer func() { q.mu.Lock(); q.running = false; q.notify(); q.mu.Unlock() }()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q.mu.Lock()
		if q.fatal != nil {
			err := q.fatal
			q.mu.Unlock()
			return err
		}
		entries, err := os.ReadDir(q.cfg.Directory)
		var files []string
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".batch") {
				files = append(files, filepath.Join(q.cfg.Directory, entry.Name()))
			}
		}
		changed := q.changed
		q.mu.Unlock()
		if err != nil {
			return err
		}
		if len(files) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-changed:
			}
			continue
		}
		sort.Strings(files)
		name := filepath.Base(files[0])
		q.mu.Lock()
		b, err := q.read(name)
		q.mu.Unlock()
		if err != nil {
			return err
		}
		for attempt := 1; ; attempt++ {
			q.mu.Lock()
			q.stats.Attempts++
			q.mu.Unlock()
			err = send(ctx, b.ID, b.Data)
			if err == nil {
				break
			}
			q.mu.Lock()
			q.stats.Failures++
			q.mu.Unlock()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt >= q.cfg.MaxAttempts {
				return fmt.Errorf("批次 %s 已尝试 %d 次，保留待重放: %w", b.ID, attempt, err)
			}
			timer := time.NewTimer(q.cfg.RetryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		q.mu.Lock()
		info, err := os.Stat(files[0])
		if err == nil {
			err = os.Remove(files[0])
		}
		if err == nil {
			err = q.syncDirectory()
		}
		if err == nil {
			q.stats.DeliveredRows += uint64(b.Rows)
			q.stats.PendingBytes -= info.Size()
			q.stats.PendingBatches--
			q.notify()
		}
		q.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (q *Queue) WaitEmpty(ctx context.Context) error {
	for {
		q.mu.Lock()
		empty := q.stats.PendingBatches == 0
		changed := q.changed
		fatal := q.fatal
		q.mu.Unlock()
		if fatal != nil {
			return fatal
		}
		if empty {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	if q.source != nil {
		s.SourceOffset = q.source.Offset
		s.SourceRows = q.source.Rows
		s.SourceSHA256 = q.source.SHA256
		s.SourceSize = q.source.Size
	}
	return s
}

// Close 必须在 Run 退出后调用；锁在整个进程持有期间有效。
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.running {
		return errors.New("先取消并等待消费者退出")
	}
	if q.closed {
		return nil
	}
	q.closed = true
	q.notify()
	if err := syscall.Flock(int(q.lock.Fd()), syscall.LOCK_UN); err != nil {
		return err
	}
	return q.lock.Close()
}
