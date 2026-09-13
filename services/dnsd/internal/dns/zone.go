// Package dns 提供 dnsd 的区域（zone）与记录内存存储骨架。
//
// 当前范围：进程内、并发安全的区域增删查，以及区域名的规范化。
// 明确不含：DNS 报文收发、区域文件（RFC 1035 master file）解析、
// 递归/转发与缓存。这些属于后续里程碑，本包先把数据模型与接口固定下来。
package dns

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrEmptyZoneName 表示区域名为空。
var ErrEmptyZoneName = errors.New("区域名不能为空")

// Record 是一条资源记录。
//
// Value 不做类型相关的语法校验（如 A 记录是否为合法 IPv4）—— 该校验依赖
// 具体记录类型语义，属于 DNS 报文层职责，此处仅保存原文以避免半吊子校验
// 带来的「看似校验了」的错觉。
type Record struct {
	// Name 是记录名（相对名或完整域名，如 "www.example.com."）。
	Name string `json:"name"`
	// Type 是记录类型，如 A / AAAA / CNAME / MX / TXT / NS。
	Type string `json:"type"`
	// TTL 是生存时间（秒）。
	TTL uint32 `json:"ttl"`
	// Value 是记录值原文。
	Value string `json:"value"`
}

// Zone 是一个 DNS 区域。
type Zone struct {
	// Name 是规范化后的区域名（小写、带结尾点），如 "example.com."。
	Name string `json:"name"`
	// Records 是该区域内的资源记录。
	Records []Record `json:"records"`
}

// NormalizeZoneName 规范化区域名：去首尾空白、转小写、补齐结尾点。
//
// DNS 域名大小写不敏感（RFC 4343），且 FQDN 语义上带结尾点。若不在入口处
// 统一，后续按名字查找会因 "Example.COM" 与 "example.com." 不一致而漏命中。
func NormalizeZoneName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// Store 是并发安全的区域存储。
type Store struct {
	mu    sync.RWMutex
	zones map[string]Zone
	order []string // 记录插入顺序，保证 List 输出稳定
}

// NewStore 构造空存储。
func NewStore() *Store {
	return &Store{zones: make(map[string]Zone)}
}

// Put 插入或覆盖一个区域（区域名会被规范化）。
//
// 返回 isNew 表示这是新增而非覆盖。
func (s *Store) Put(z Zone) (isNew bool, err error) {
	name := NormalizeZoneName(z.Name)
	if name == "" {
		return false, ErrEmptyZoneName
	}
	z.Name = name
	// 复制 Records，避免调用方后续修改切片影响存储内部状态。
	z.Records = append([]Record(nil), z.Records...)

	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.zones[name]
	if !exists {
		s.order = append(s.order, name)
	}
	s.zones[name] = z
	return !exists, nil
}

// Get 按区域名查询（自动规范化入参）。
func (s *Store) Get(name string) (Zone, bool) {
	key := NormalizeZoneName(name)
	if key == "" {
		return Zone{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	z, ok := s.zones[key]
	if !ok {
		return Zone{}, false
	}
	// 返回深拷贝，防止调用方修改记录切片污染存储。
	z.Records = append([]Record(nil), z.Records...)
	return z, true
}

// List 按插入顺序返回全部区域的副本。
func (s *Store) List() []Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Zone, 0, len(s.order))
	for _, name := range s.order {
		if z, ok := s.zones[name]; ok {
			z.Records = append([]Record(nil), z.Records...)
			out = append(out, z)
		}
	}
	return out
}

// Delete 删除区域，返回是否确实删除。
func (s *Store) Delete(name string) bool {
	key := NormalizeZoneName(name)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.zones[key]; !ok {
		return false
	}
	delete(s.zones, key)
	for i, v := range s.order {
		if v == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return true
}

// Count 返回区域总数。
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.zones)
}

// RecordCount 返回全部区域的记录总数。
func (s *Store) RecordCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := 0
	for _, z := range s.zones {
		n += len(z.Records)
	}
	return n
}

// Load 批量载入区域（全量替换语义）。
//
// 先全量校验再替换，避免「载入一半失败」留下不一致状态。
func (s *Store) Load(zones []Zone) error {
	loaded := make(map[string]Zone, len(zones))
	order := make([]string, 0, len(zones))

	for i, z := range zones {
		name := NormalizeZoneName(z.Name)
		if name == "" {
			return fmt.Errorf("%w（第 %d 个区域）", ErrEmptyZoneName, i)
		}
		if _, dup := loaded[name]; dup {
			return fmt.Errorf("重复的区域名 %q（第 %d 个区域）", name, i)
		}
		z.Name = name
		z.Records = append([]Record(nil), z.Records...)
		loaded[name] = z
		order = append(order, name)
	}

	s.mu.Lock()
	s.zones = loaded
	s.order = order
	s.mu.Unlock()
	return nil
}
