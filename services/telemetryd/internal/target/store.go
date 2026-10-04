// Package target 提供 telemetryd 的抓取目标注册表。
//
// 本包是 CYS-TEL-003（抓取调度器）的数据模型前置：调度器需要一份
// 「抓谁、多久抓一次、超时多久」的目标定义，本包先把该模型与校验
// 规则固定下来，并提供并发安全的增删查。
//
// 明确不含：实际发起 HTTP 抓取、调度循环、重试与失败计数。这些属于
// CYS-TEL-003 及其后续任务。
package target

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 校验失败原因（供调用方与测试按需判断）。
var (
	ErrEmptyName     = errors.New("目标名不能为空")
	ErrInvalidURL    = errors.New("抓取地址必须是合法的 http/https URL")
	ErrBadInterval   = errors.New("抓取间隔必须为正")
	ErrBadTimeout    = errors.New("抓取超时必须为正")
	ErrTimeoutTooBig = errors.New("抓取超时必须小于抓取间隔")
	ErrBadLabelName  = errors.New("标签名不能为空")
)

// DefaultIntervalSeconds 是未指定抓取间隔时的默认值。
//
// 15 秒与 Prometheus 的常见默认一致：足够新鲜，又不会让被采集服务的
// 指标聚合产生可观开销。
const DefaultIntervalSeconds = 15

// DefaultTimeoutSeconds 是未指定抓取超时时的默认值。
//
// 取抓取间隔的 2/3 是刻意的保守选择：给「慢但没死」的目标留出重试窗口，
// 而不是把超时拉满到与间隔相等（那样一次慢响应会顶掉下一次抓取）。
const DefaultTimeoutSeconds = 10

// Target 是一个抓取目标。
//
// 时间字段刻意用「秒」的整数而非 time.Duration：本结构直接作为控制面
// JSON 契约对外暴露，而 time.Duration 的 JSON 表示是纳秒整数，写进配置文件
// 或交给前端都会产生歧义。对外用秒、对内用 Duration() 换算，两不相扰。
type Target struct {
	// Name 是目标的唯一标识（如 "routerd"、"policyd"）。
	Name string `json:"name"`
	// URL 是抓取地址，必须是 http/https，通常指向某服务的 /metrics。
	URL string `json:"url"`
	// IntervalSeconds 是抓取间隔（秒）；0 表示使用 DefaultIntervalSeconds。
	IntervalSeconds int `json:"interval_seconds,omitempty"`
	// TimeoutSeconds 是单次抓取超时（秒）；0 表示使用 DefaultTimeoutSeconds。
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Enabled 为 false 时目标被登记但不被抓取。
	Enabled bool `json:"enabled"`
	// Labels 是附加到该目标采集数据的静态标签（如 {"env":"prod"}）。
	Labels map[string]string `json:"labels,omitempty"`
}

// Interval 返回生效的抓取间隔（应用默认值后）。
func (t Target) Interval() time.Duration {
	return time.Duration(t.effectiveIntervalSeconds()) * time.Second
}

// Timeout 返回生效的抓取超时（应用默认值后）。
func (t Target) Timeout() time.Duration {
	return time.Duration(t.effectiveTimeoutSeconds()) * time.Second
}

func (t Target) effectiveIntervalSeconds() int {
	if t.IntervalSeconds > 0 {
		return t.IntervalSeconds
	}
	return DefaultIntervalSeconds
}

func (t Target) effectiveTimeoutSeconds() int {
	if t.TimeoutSeconds > 0 {
		return t.TimeoutSeconds
	}
	return DefaultTimeoutSeconds
}

// Validate 校验目标定义。
//
// 校验在登记入口统一执行，而非留给调用方 —— 一个「间隔为 0」的目标若被
// 放进存储，调度器要么忙轮询要么静默不抓，两种都是难查的故障。
func (t Target) Validate() error {
	if strings.TrimSpace(t.Name) == "" {
		return ErrEmptyName
	}
	if err := ValidateURL(t.URL); err != nil {
		return err
	}
	if t.IntervalSeconds < 0 {
		return fmt.Errorf("%w: %d", ErrBadInterval, t.IntervalSeconds)
	}
	if t.TimeoutSeconds < 0 {
		return fmt.Errorf("%w: %d", ErrBadTimeout, t.TimeoutSeconds)
	}
	// 超时必须严格小于间隔。相等也非法：一次卡在超时边界上的响应会与下一次
	// 抓取首尾相接，长期看会把实际抓取周期拉长一倍而不报错。
	if t.effectiveTimeoutSeconds() >= t.effectiveIntervalSeconds() {
		return fmt.Errorf("%w: 超时 %ds >= 间隔 %ds",
			ErrTimeoutTooBig, t.effectiveTimeoutSeconds(), t.effectiveIntervalSeconds())
	}
	for k := range t.Labels {
		if strings.TrimSpace(k) == "" {
			return ErrBadLabelName
		}
	}
	return nil
}

// ValidateURL 校验抓取地址。
//
// 只接受 http/https：Prometheus 文本格式的抓取走 HTTP，其他 scheme
// （file:、ftp:）要么语义不同要么需要额外凭据，一律拒绝比半支持更清楚。
func ValidateURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: 地址为空", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme=%q", ErrInvalidURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: 缺少主机名", ErrInvalidURL)
	}
	return nil
}

// Store 是并发安全的抓取目标注册表。
type Store struct {
	mu      sync.RWMutex
	targets map[string]Target
	order   []string // 记录插入顺序，保证 List 输出稳定
}

// NewStore 构造空注册表。
func NewStore() *Store {
	return &Store{targets: make(map[string]Target)}
}

// Put 登记或覆盖一个目标（目标名会被规整首尾空白）。
//
// 返回 isNew 表示这是新增而非覆盖。
func (s *Store) Put(t Target) (isNew bool, err error) {
	t.Name = strings.TrimSpace(t.Name)
	if err := t.Validate(); err != nil {
		return false, err
	}
	// 复制标签表，避免调用方后续修改污染存储内部状态。
	t.Labels = copyLabels(t.Labels)

	key := t.Name
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.targets[key]
	if !exists {
		s.order = append(s.order, key)
	}
	s.targets[key] = t
	return !exists, nil
}

// Get 按名查询目标。
func (s *Store) Get(name string) (Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.targets[strings.TrimSpace(name)]
	if !ok {
		return Target{}, false
	}
	t.Labels = copyLabels(t.Labels)
	return t, true
}

// List 按插入顺序返回全部目标。
func (s *Store) List() []Target {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Target, 0, len(s.order))
	for _, name := range s.order {
		if t, ok := s.targets[name]; ok {
			t.Labels = copyLabels(t.Labels)
			out = append(out, t)
		}
	}
	return out
}

// Enabled 按插入顺序返回启用中的目标（调度器实际抓取的集合）。
func (s *Store) Enabled() []Target {
	all := s.List()
	out := make([]Target, 0, len(all))
	for _, t := range all {
		if t.Enabled {
			out = append(out, t)
		}
	}
	return out
}

// Delete 删除目标，返回是否确实删除。
func (s *Store) Delete(name string) bool {
	key := strings.TrimSpace(name)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.targets[key]; !ok {
		return false
	}
	delete(s.targets, key)
	for i, v := range s.order {
		if v == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return true
}

// Count 返回目标总数。
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.targets)
}

// Load 批量载入目标（全量替换语义）。
//
// 先全量校验再替换，避免「载入一半失败」留下不一致状态。
// 刻意不校验「同名重复」之外的一致性：目标之间彼此独立，
// 不存在 dnsd 那样的区域层级关系。
func (s *Store) Load(targets []Target) error {
	loaded := make(map[string]Target, len(targets))
	order := make([]string, 0, len(targets))

	for i, t := range targets {
		t.Name = strings.TrimSpace(t.Name)
		if err := t.Validate(); err != nil {
			return fmt.Errorf("第 %d 个目标无效: %w", i, err)
		}
		if _, dup := loaded[t.Name]; dup {
			return fmt.Errorf("重复的目标名 %q（第 %d 个）", t.Name, i)
		}
		t.Labels = copyLabels(t.Labels)
		loaded[t.Name] = t
		order = append(order, t.Name)
	}

	s.mu.Lock()
	s.targets = loaded
	s.order = order
	s.mu.Unlock()
	return nil
}

// copyLabels 返回标签表的副本；nil 输入返回 nil（保持 omitempty 语义）。
func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
