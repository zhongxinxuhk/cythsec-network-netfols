// Package policy 提供 policyd 的策略内存存储骨架。
//
// 当前实现只覆盖「进程内、并发安全、可按 ID 增删查」的最小能力，目的是先打通
// 控制面链路（HTTP -> 存储 -> 指标）并把接口形状固定下来。
//
// 明确不属于本包的范围：策略持久化、规则表达式编译、向数据面下发。
// 这些属于 M3 之后的里程碑，待对应任务落地时再扩展实现，接口保持不变。
package policy

import (
	"errors"
	"fmt"
	"sync"
)

// ErrEmptyID 表示规则 ID 为空。
var ErrEmptyID = errors.New("规则 ID 不能为空")

// Rule 是一条访问控制策略规则。
//
// Expression 当前仅作字符串保存与回显 —— 语法校验与编译在后续任务中实现，
// 因此在 API 层不对其做任何「看起来已支持」的承诺。
type Rule struct {
	// ID 是规则唯一标识。
	ID string `json:"id"`
	// Name 是人类可读名称。
	Name string `json:"name"`
	// Priority 是匹配优先级，数值越小越优先。
	Priority int `json:"priority"`
	// Enabled 表示规则是否参与匹配。
	Enabled bool `json:"enabled"`
	// Expression 是规则表达式原文（尚未编译）。
	Expression string `json:"expression,omitempty"`
}

// Store 是并发安全的策略规则内存存储。
//
// 使用 RWMutex 而非 sync.Map：读多写少且需要保持插入顺序遍历，
// Map 的遍历顺序不确定，无法满足 List 的稳定输出要求。
type Store struct {
	mu    sync.RWMutex
	rules map[string]Rule
	order []string // 记录插入顺序，保证 List 输出稳定
}

// NewStore 构造空存储。
func NewStore() *Store {
	return &Store{rules: make(map[string]Rule)}
}

// Put 插入或覆盖一条规则；ID 为空时返回 ErrEmptyID。
//
// 返回 isNew 表示这是新增（而非覆盖），便于调用方统计。
func (s *Store) Put(r Rule) (isNew bool, err error) {
	if r.ID == "" {
		return false, ErrEmptyID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.rules[r.ID]
	if !exists {
		s.order = append(s.order, r.ID)
	}
	s.rules[r.ID] = r
	return !exists, nil
}

// Get 按 ID 查询规则。
func (s *Store) Get(id string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return r, ok
}

// List 按插入顺序返回全部规则的副本（调用方可安全修改返回值）。
func (s *Store) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Rule, 0, len(s.order))
	for _, id := range s.order {
		if r, ok := s.rules[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

// Delete 删除规则，返回是否确实删除了条目。
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rules[id]; !ok {
		return false
	}
	delete(s.rules, id)
	for i, v := range s.order {
		if v == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return true
}

// Count 返回当前规则条数。
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// Load 从切片批量载入规则（如启动时从策略文件读取）。
//
// 采用「全量替换」语义：先清空再写入，避免残留上一份配置的规则。
// 任一条目非法时立即返回错误并附带索引，便于定位配置文件问题。
func (s *Store) Load(rules []Rule) error {
	loaded := make(map[string]Rule, len(rules))
	order := make([]string, 0, len(rules))
	for i, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("%w（第 %d 条）", ErrEmptyID, i)
		}
		if _, dup := loaded[r.ID]; dup {
			return fmt.Errorf("重复的规则 ID %q（第 %d 条）", r.ID, i)
		}
		loaded[r.ID] = r
		order = append(order, r.ID)
	}

	s.mu.Lock()
	s.rules = loaded
	s.order = order
	s.mu.Unlock()
	return nil
}
