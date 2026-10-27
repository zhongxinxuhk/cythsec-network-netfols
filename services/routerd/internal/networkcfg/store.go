package networkcfg

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var ErrConflict = errors.New("配置版本已变化，请重新读取后比较")

type Snapshot struct {
	Revision  uint64     `json:"revision"`
	UpdatedAt *time.Time `json:"updated_at"`
	Stage     string     `json:"stage"`
	Config    Config     `json:"config"`
}
type Store struct {
	mu       sync.Mutex
	dir      string
	snapshot Snapshot
	lock     *os.File
	closed   bool
}

func Empty() Snapshot {
	return Snapshot{Stage: "unconfigured", Config: Config{Backend: "netplan", Interfaces: []Interface{}}}
}
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("network configuration directory must be private")
	}
	lockPath := filepath.Join(dir, ".lock")
	if st, e := os.Lstat(lockPath); e == nil && !st.Mode().IsRegular() {
		return nil, errors.New("invalid configuration lock")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			lock.Close()
		}
	}()
	s := &Store{dir: dir, snapshot: Empty(), lock: lock}
	path := filepath.Join(dir, "desired.json")
	info, err = os.Lstat(path)
	if os.IsNotExist(err) {
		ready = true
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 131072 {
		return nil, errors.New("invalid network configuration file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 131073))
	d.DisallowUnknownFields()
	if err = d.Decode(&s.snapshot); err != nil {
		return nil, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF || s.snapshot.Revision == 0 || s.snapshot.Stage != "draft_saved" || s.snapshot.UpdatedAt == nil {
		return nil, errors.New("invalid saved network state")
	}
	if err = Validate(s.snapshot.Config); err != nil {
		return nil, err
	}
	ready = true
	return s, nil
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
func clone(s Snapshot) Snapshot {
	raw, _ := json.Marshal(s)
	var copy Snapshot
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (s *Store) Read() Snapshot { s.mu.Lock(); defer s.mu.Unlock(); return clone(s.snapshot) }
func (s *Store) Save(expected uint64, c Config) (Snapshot, error) {
	if err := Validate(c); err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Snapshot{}, errors.New("configuration store closed")
	}
	if expected == ^uint64(0) {
		return Snapshot{}, errors.New("configuration revision exhausted")
	}
	if expected != s.snapshot.Revision {
		return Snapshot{}, ErrConflict
	}
	now := time.Now().UTC()
	next := Snapshot{Revision: expected + 1, UpdatedAt: &now, Stage: "draft_saved", Config: c}
	raw, err := json.Marshal(next)
	if err != nil {
		return Snapshot{}, err
	}
	f, err := os.CreateTemp(s.dir, ".desired-*")
	if err != nil {
		return Snapshot{}, err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return Snapshot{}, err
	}
	if err = os.Rename(temp, filepath.Join(s.dir, "desired.json")); err != nil {
		return Snapshot{}, err
	}
	// Rename may already have committed if directory sync fails: force a reload on retry.
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
