// Package dpipolicy 提供 DPI 模块策略的持久化与控制面校验。
//
// 它与数据面的关系是**文件契约**：routerd 原子写入 policy.json，traffic-engine
// 通过 --dpi-policy 读取同一份 JSON。控制面不假装自己已经改变正在运行的数据面
// 进程，只保证"下一次启动/下一次分析读到的是这份策略"。
package dpipolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const SchemaVersion = 1

// ErrConflict 表示 If-Match 版本已过期。
var ErrConflict = errors.New("DPI 策略版本已变化，请重新读取后比较")

// TLSDecrypt 只接受运维方提供的 NSS key log，不包含任何主动探测或破解配置。
type TLSDecrypt struct {
	Enabled    bool   `json:"enabled"`
	KeylogFile string `json:"keylog_file"`
}

// Policy 与 Rust `dpi::DpiPolicy` 的 JSON 契约一一对应。
type Policy struct {
	SchemaVersion int             `json:"schema_version"`
	Enabled       bool            `json:"enabled"`
	Intensity     string          `json:"intensity"`
	InspectBytes  *int            `json:"inspect_bytes"`
	Modules       map[string]bool `json:"modules"`
	TLSDecrypt    TLSDecrypt      `json:"tls_decrypt"`
}

// Snapshot 是带版本的策略状态。
type Snapshot struct {
	Revision  uint64     `json:"revision"`
	UpdatedAt *time.Time `json:"updated_at"`
	Policy    Policy     `json:"policy"`
}

// Module 是控制台展示用的模块目录项；键与 Rust `AppId` 一一对应。
type Module struct {
	Key            string   `json:"key"`
	Name           string   `json:"name"`
	Group          string   `json:"group"`
	Availability   string   `json:"availability"`
	CatalogIDs     []string `json:"catalog_ids"`
	DefaultEnabled bool     `json:"default_enabled"`
	Note           string   `json:"note,omitempty"`
}

// Default 返回标准强度、全部已实现模块启用的策略。
func Default() Policy {
	modules := make(map[string]bool, len(Modules))
	for _, module := range Modules {
		modules[module.Key] = module.DefaultEnabled
	}
	return Policy{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		Intensity:     "standard",
		Modules:       modules,
	}
}

// Normalize 填充缺省字段；它不替代 Validate，未知键仍会被拒绝。
func Normalize(policy Policy) Policy {
	policy.SchemaVersion = SchemaVersion
	if policy.Intensity == "" {
		policy.Intensity = "standard"
	}
	if policy.Modules == nil {
		policy.Modules = map[string]bool{}
	}
	for _, module := range Modules {
		if _, ok := policy.Modules[module.Key]; !ok {
			policy.Modules[module.Key] = module.DefaultEnabled
		}
	}
	return policy
}

// Validate 严格校验策略。拼错的模块键、非法强度、相对密钥路径都必须报错。
func Validate(policy Policy) error {
	if policy.SchemaVersion != SchemaVersion {
		return fmt.Errorf("不支持的 schema_version=%d", policy.SchemaVersion)
	}
	switch policy.Intensity {
	case "off", "basic", "standard", "deep":
	default:
		return fmt.Errorf("未知 DPI 强度 %q", policy.Intensity)
	}
	if policy.InspectBytes != nil && (*policy.InspectBytes < 64 || *policy.InspectBytes > 65536) {
		return fmt.Errorf("inspect_bytes=%d 超出 64..=65536", *policy.InspectBytes)
	}
	known := make(map[string]bool, len(Modules))
	for _, module := range Modules {
		known[module.Key] = true
	}
	for key := range policy.Modules {
		if !known[key] {
			return fmt.Errorf("未知 DPI 模块 %q", key)
		}
	}
	if policy.TLSDecrypt.KeylogFile != "" {
		path := policy.TLSDecrypt.KeylogFile
		if len(path) > 4096 || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) {
			return errors.New("tls_decrypt.keylog_file 必须是不超过 4096 字节的绝对路径")
		}
	}
	return nil
}

// Store 是带进程锁与原子替换的策略存储。
type Store struct {
	mu       sync.Mutex
	dir      string
	snapshot Snapshot
	lock     *os.File
	closed   bool
}

// Open 打开（或初始化）私有目录中的 DPI 策略存储。
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("DPI policy directory must be private")
	}
	lockPath := filepath.Join(dir, ".lock")
	if st, e := os.Lstat(lockPath); e == nil && !st.Mode().IsRegular() {
		return nil, errors.New("invalid DPI policy lock")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	store := &Store{
		dir: dir,
		snapshot: Snapshot{
			Policy: Default(),
		},
		lock: lock,
	}
	path := filepath.Join(dir, "policy.json")
	info, err = os.Lstat(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 131072 {
		lock.Close()
		return nil, errors.New("invalid DPI policy file")
	}
	file, err := os.Open(path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&store.snapshot); err != nil {
		lock.Close()
		return nil, err
	}
	if store.snapshot.Revision == 0 || store.snapshot.UpdatedAt == nil {
		lock.Close()
		return nil, errors.New("invalid saved DPI policy state")
	}
	store.snapshot.Policy = Normalize(store.snapshot.Policy)
	if err = Validate(store.snapshot.Policy); err != nil {
		lock.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.lock.Close()
}

func clone(snapshot Snapshot) Snapshot {
	raw, _ := json.Marshal(snapshot)
	var copy Snapshot
	_ = json.Unmarshal(raw, &copy)
	return copy
}

// Read 返回当前快照的副本。
func (s *Store) Read() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.snapshot)
}

// Empty 返回未启用存储时的只读默认状态。
func Empty() Snapshot {
	return Snapshot{Policy: Default()}
}

// Save 以 If-Match 语义写入并原子替换 policy.json。
func (s *Store) Save(expected uint64, policy Policy) (Snapshot, error) {
	policy = Normalize(policy)
	if err := Validate(policy); err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Snapshot{}, errors.New("DPI policy store closed")
	}
	if expected == ^uint64(0) {
		return Snapshot{}, errors.New("DPI policy revision exhausted")
	}
	if expected != s.snapshot.Revision {
		return Snapshot{}, ErrConflict
	}
	now := time.Now().UTC()
	next := Snapshot{Revision: expected + 1, UpdatedAt: &now, Policy: policy}
	raw, err := json.Marshal(next)
	if err != nil {
		return Snapshot{}, err
	}
	file, err := os.CreateTemp(s.dir, ".policy-*")
	if err != nil {
		return Snapshot{}, err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return Snapshot{}, err
	}
	if err = os.Rename(temp, filepath.Join(s.dir, "policy.json")); err != nil {
		return Snapshot{}, err
	}
	s.snapshot = clone(next)
	dir, err := os.Open(s.dir)
	if err != nil {
		return Snapshot{}, err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return Snapshot{}, err
	}
	return clone(next), nil
}
