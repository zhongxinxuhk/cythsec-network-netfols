package aggregate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const MaxStoreBytes int64 = 64 << 20
const MaxImports = 1024

var ErrFull = errors.New("aggregate store capacity reached")
var ErrNotFound = errors.New("aggregate import not found")

type Import struct {
	ID       string  `json:"id"`
	StoredAt string  `json:"stored_at"`
	Windows  int     `json:"windows"`
	First    *uint64 `json:"first_window_seconds"`
	Last     *uint64 `json:"last_window_seconds"`
	Bytes    int64   `json:"bytes"`
	Status   Status  `json:"status"`
}
type Page struct {
	Import Import   `json:"import"`
	Items  []Window `json:"items"`
	Total  int      `json:"total"`
	Offset int      `json:"offset"`
	Limit  int      `json:"limit"`
}
type Store struct {
	mu       sync.Mutex
	dir      string
	lock     *os.File
	items    map[string]Import
	bytes    int64
	maxBytes int64
	failed   bool
}

func digest(data []byte) string { v := sha256.Sum256(data); return hex.EncodeToString(v[:]) }
func metadata(id string, b Batch, size int64, mod time.Time) Import {
	m := Import{ID: id, StoredAt: mod.UTC().Format(time.RFC3339Nano), Windows: len(b.Windows), Bytes: size, Status: b.Status}
	if len(b.Windows) > 0 {
		a, z := b.Windows[0].Start, b.Windows[len(b.Windows)-1].Start
		m.First = &a
		m.Last = &z
	}
	return m
}

// Open validates every committed file before serving. A single writer lock,
// synced immutable files and directory fsync make retry after interruption safe.
// ponytail: bounded local archive; use a measured columnar backend for scale.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("aggregate directory must be private")
	}
	lockPath := filepath.Join(dir, ".lock")
	if st, err := os.Lstat(lockPath); err == nil && !st.Mode().IsRegular() {
		return nil, errors.New("invalid aggregate lock")
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	s := &Store{dir: dir, lock: f, items: make(map[string]Import), maxBytes: MaxStoreBytes}
	fail := func(err error) (*Store, error) { s.Close(); return nil, err }
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fail(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pending-") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return fail(err)
			}
			continue
		}
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".jsonl")
		b, data, info, err := s.read(id)
		if err != nil {
			return fail(err)
		}
		s.items[id] = metadata(id, b, int64(len(data)), info.ModTime())
		s.bytes += int64(len(data))
		if len(s.items) > MaxImports || s.bytes > s.maxBytes {
			return fail(ErrFull)
		}
	}
	return s, nil
}
func validID(id string) bool {
	v, err := hex.DecodeString(id)
	return err == nil && len(v) == 32 && id == strings.ToLower(id)
}
func (s *Store) read(id string) (Batch, []byte, os.FileInfo, error) {
	if !validID(id) {
		return Batch{}, nil, nil, ErrNotFound
	}
	p := filepath.Join(s.dir, id+".jsonl")
	info, err := os.Lstat(p)
	if err != nil {
		return Batch{}, nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBatchBytes || info.Mode().Perm()&0077 != 0 {
		return Batch{}, nil, nil, ErrInvalid
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return Batch{}, nil, nil, err
	}
	if digest(data) != id {
		return Batch{}, nil, nil, ErrInvalid
	}
	b, err := Parse(data)
	return b, data, info, err
}
func (s *Store) syncDir() error {
	f, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
func (s *Store) Put(data []byte) (Import, bool, error) {
	b, err := Parse(data)
	if err != nil {
		return Import{}, false, err
	}
	data = canonical(b)
	id := digest(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil || s.failed {
		return Import{}, false, os.ErrClosed
	}
	if m, ok := s.items[id]; ok {
		if _, _, _, err := s.read(id); err != nil {
			return Import{}, false, err
		}
		return m, true, s.syncDir()
	}
	if len(s.items) >= MaxImports || s.bytes+int64(len(data)) > s.maxBytes {
		return Import{}, false, ErrFull
	}
	f, err := os.CreateTemp(s.dir, ".pending-")
	if err != nil {
		return Import{}, false, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return Import{}, false, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return Import{}, false, err
	}
	if err = f.Close(); err != nil {
		return Import{}, false, err
	}
	dst := filepath.Join(s.dir, id+".jsonl")
	if err = os.Link(f.Name(), dst); err != nil {
		// A previous attempt may have committed before a directory-sync failure.
		if !os.IsExist(err) {
			return Import{}, false, err
		}
		if _, _, _, err = s.read(id); err != nil {
			return Import{}, false, err
		}
	}
	if err = s.syncDir(); err != nil {
		s.failed = true // Commit outcome uncertain: restart and validate before another write.
		return Import{}, false, err
	}
	info, err := os.Stat(dst)
	if err != nil {
		return Import{}, false, err
	}
	m := metadata(id, b, int64(len(data)), info.ModTime())
	s.items[id] = m
	s.bytes += m.Bytes
	return m, false, nil
}
func (s *Store) List() []Import {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]Import, 0, len(s.items))
	for _, m := range s.items {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].StoredAt == list[j].StoredAt {
			return list[i].ID < list[j].ID
		}
		return list[i].StoredAt > list[j].StoredAt
	})
	return list
}

// Query keeps imports separate: overlapping captures must never be silently summed.
func (s *Store) Query(id string, from, to uint64, offset, limit int) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return Page{}, os.ErrClosed
	}
	m, ok := s.items[id]
	if !ok {
		return Page{}, ErrNotFound
	}
	b, _, _, err := s.read(id)
	if err != nil {
		return Page{}, err
	}
	if to <= from || offset < 0 || limit < 1 || limit > 100 {
		return Page{}, ErrInvalid
	}
	filtered := make([]Window, 0)
	for _, w := range b.Windows {
		if w.Start >= from && w.Start < to {
			filtered = append(filtered, w)
		}
	}
	page := Page{Import: m, Items: make([]Window, 0), Total: len(filtered), Offset: offset, Limit: limit}
	if offset < len(filtered) {
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		page.Items = filtered[offset:end]
	}
	return page, nil
}
