// 本文件实现三类核心指标：Counter、Gauge、Histogram，以及各自的带标签
// （Vec）变体。全部类型均可安全并发使用。
package metrics

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// labelNameRE 是 Prometheus 对标签名的字符集要求。
var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// DefaultBuckets 是 HTTP 延迟等场景的默认直方图分桶（单位：秒）。
var DefaultBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// newFamily 校验参数并返回指标全名。
func newFamily(kind, subsystem, metric, unit string) string {
	name, err := BuildName(subsystem, metric, unit)
	if err != nil {
		panic(fmt.Sprintf("metrics: %s/%s: %v", kind, metric, err))
	}
	if err := ValidateName(kind, name); err != nil {
		panic(fmt.Sprintf("metrics: %s/%s: %v", kind, metric, err))
	}
	return name
}

// checkLabelNames 校验标签名合法性并检测重复。
func checkLabelNames(names []string) {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if !labelNameRE.MatchString(n) {
			panic("metrics: 非法标签名: " + n)
		}
		if n == "le" {
			panic("metrics: 标签名 le 为直方图保留字，不可使用")
		}
		if seen[n] {
			panic("metrics: 标签名重复: " + n)
		}
		seen[n] = true
	}
}

// ---------------------------------------------------------------- Counter

// Counter 是只增不减的累计计数器。
type Counter struct {
	name   string
	help   string
	labels string
	v      atomic.Uint64
}

// NewCounter 构造无标签计数器。unit 通常为 "total"。
func NewCounter(subsystem, metric, unit, help string) *Counter {
	return &Counter{name: newFamily("counter", subsystem, metric, unit), help: help}
}

// Name 返回指标全名。
func (c *Counter) Name() string { return c.name }

// Help 返回帮助文本。
func (c *Counter) Help() string { return c.help }

// Type 返回 "counter"。
func (c *Counter) Type() string { return "counter" }

// WriteSamples 写出样本行。
func (c *Counter) WriteSamples(sb *strings.Builder) {
	appendSample(sb, c.name, c.labels, float64(c.v.Load()))
}

// Inc 计数加一。
func (c *Counter) Inc() { c.v.Add(1) }

// Add 计数加 delta。
func (c *Counter) Add(delta uint64) { c.v.Add(delta) }

// Value 返回当前累计值。
func (c *Counter) Value() uint64 { return c.v.Load() }

// CounterVec 是带标签的计数器族。
type CounterVec struct {
	name       string
	help       string
	labelNames []string
	mu         sync.RWMutex
	children   map[string]*Counter
}

// NewCounterVec 构造带标签计数器族。unit 通常为 "total"。
func NewCounterVec(subsystem, metric, unit, help string, labelNames ...string) *CounterVec {
	checkLabelNames(labelNames)
	return &CounterVec{
		name:       newFamily("counter", subsystem, metric, unit),
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		children:   make(map[string]*Counter),
	}
}

// Name 返回指标全名。
func (v *CounterVec) Name() string { return v.name }

// Help 返回帮助文本。
func (v *CounterVec) Help() string { return v.help }

// Type 返回 "counter"。
func (v *CounterVec) Type() string { return "counter" }

// WriteSamples 写出全部子样本（标签按注册顺序，族内按标签串字典序）。
func (v *CounterVec) WriteSamples(sb *strings.Builder) {
	for _, c := range v.snapshot() {
		c.WriteSamples(sb)
	}
}

// WithLabelValues 返回指定标签组合的计数器，不存在则创建。
// 标签个数必须与声明一致，否则返回错误。
func (v *CounterVec) WithLabelValues(values ...string) (*Counter, error) {
	key, err := v.keyOf(values)
	if err != nil {
		return nil, err
	}
	v.mu.RLock()
	c, ok := v.children[key]
	v.mu.RUnlock()
	if ok {
		return c, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok = v.children[key]; ok {
		return c, nil
	}
	c = &Counter{name: v.name, help: v.help, labels: key}
	v.children[key] = c
	return c, nil
}

// MustWithLabelValues 是 WithLabelValues 的 panic 版本。
func (v *CounterVec) MustWithLabelValues(values ...string) *Counter {
	c, err := v.WithLabelValues(values...)
	if err != nil {
		panic("metrics: " + v.name + ": " + err.Error())
	}
	return c
}

// Delete 移除指定标签组合的子指标（用于清理不再活跃的标签，避免基数膨胀）。
func (v *CounterVec) Delete(values ...string) {
	key, err := v.keyOf(values)
	if err != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.children, key)
}

// Reset 清空全部子指标。
func (v *CounterVec) Reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.children = make(map[string]*Counter)
}

// snapshot 返回按标签串排序的子指标切片（保证输出稳定）。
func (v *CounterVec) snapshot() []*Counter {
	v.mu.RLock()
	keys := make([]string, 0, len(v.children))
	for k := range v.children {
		keys = append(keys, k)
	}
	v.mu.RUnlock()
	sortStrings(keys)
	out := make([]*Counter, 0, len(keys))
	for _, k := range keys {
		v.mu.RLock()
		c := v.children[k]
		v.mu.RUnlock()
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// keyOf 把标签值渲染为 `{k="v",...}`，并校验个数。
func (v *CounterVec) keyOf(values []string) (string, error) {
	if len(values) != len(v.labelNames) {
		return "", fmt.Errorf("标签个数不匹配: 期望 %d 个 %v，实际 %d 个",
			len(v.labelNames), v.labelNames, len(values))
	}
	return renderLabels(v.labelNames, values), nil
}

// ---------------------------------------------------------------- Gauge

// Gauge 是可增可减的瞬时值指标（float64）。
type Gauge struct {
	name   string
	help   string
	labels string
	bits   atomic.Uint64 // 以 math.Float64bits 存储
}

// NewGauge 构造无标签仪表。
func NewGauge(subsystem, metric, unit, help string) *Gauge {
	return &Gauge{name: newFamily("gauge", subsystem, metric, unit), help: help}
}

// Name 返回指标全名。
func (g *Gauge) Name() string { return g.name }

// Help 返回帮助文本。
func (g *Gauge) Help() string { return g.help }

// Type 返回 "gauge"。
func (g *Gauge) Type() string { return "gauge" }

// WriteSamples 写出样本行。
func (g *Gauge) WriteSamples(sb *strings.Builder) {
	appendSample(sb, g.name, g.labels, g.Value())
}

// Set 设为指定值。
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Value 返回当前值。
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

// Inc 加一。
func (g *Gauge) Inc() { g.Add(1) }

// Dec 减一。
func (g *Gauge) Dec() { g.Add(-1) }

// Add 增减 delta（用 CAS 循环保证并发安全）。
func (g *Gauge) Add(delta float64) {
	for {
		old := g.bits.Load()
		nv := math.Float64bits(math.Float64frombits(old) + delta)
		if g.bits.CompareAndSwap(old, nv) {
			return
		}
	}
}

// GaugeVec 是带标签的仪表族。
type GaugeVec struct {
	name       string
	help       string
	labelNames []string
	mu         sync.RWMutex
	children   map[string]*Gauge
}

// NewGaugeVec 构造带标签仪表族。
func NewGaugeVec(subsystem, metric, unit, help string, labelNames ...string) *GaugeVec {
	checkLabelNames(labelNames)
	return &GaugeVec{
		name:       newFamily("gauge", subsystem, metric, unit),
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		children:   make(map[string]*Gauge),
	}
}

// Name 返回指标全名。
func (v *GaugeVec) Name() string { return v.name }

// Help 返回帮助文本。
func (v *GaugeVec) Help() string { return v.help }

// Type 返回 "gauge"。
func (v *GaugeVec) Type() string { return "gauge" }

// WriteSamples 写出全部子样本。
func (v *GaugeVec) WriteSamples(sb *strings.Builder) {
	keys := v.keys()
	for _, k := range keys {
		v.mu.RLock()
		g := v.children[k]
		v.mu.RUnlock()
		if g != nil {
			g.WriteSamples(sb)
		}
	}
}

// WithLabelValues 返回指定标签组合的仪表，不存在则创建。
func (v *GaugeVec) WithLabelValues(values ...string) (*Gauge, error) {
	key, err := v.keyOf(values)
	if err != nil {
		return nil, err
	}
	v.mu.RLock()
	g, ok := v.children[key]
	v.mu.RUnlock()
	if ok {
		return g, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if g, ok = v.children[key]; ok {
		return g, nil
	}
	g = &Gauge{name: v.name, help: v.help, labels: key}
	v.children[key] = g
	return g, nil
}

// MustWithLabelValues 是 WithLabelValues 的 panic 版本。
func (v *GaugeVec) MustWithLabelValues(values ...string) *Gauge {
	g, err := v.WithLabelValues(values...)
	if err != nil {
		panic("metrics: " + v.name + ": " + err.Error())
	}
	return g
}

// Delete 移除指定标签组合的子指标。
func (v *GaugeVec) Delete(values ...string) {
	key, err := v.keyOf(values)
	if err != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.children, key)
}

func (v *GaugeVec) keyOf(values []string) (string, error) {
	if len(values) != len(v.labelNames) {
		return "", fmt.Errorf("标签个数不匹配: 期望 %d 个 %v，实际 %d 个",
			len(v.labelNames), v.labelNames, len(values))
	}
	return renderLabels(v.labelNames, values), nil
}

func (v *GaugeVec) keys() []string {
	v.mu.RLock()
	keys := make([]string, 0, len(v.children))
	for k := range v.children {
		keys = append(keys, k)
	}
	v.mu.RUnlock()
	sortStrings(keys)
	return keys
}

// -------------------------------------------------------------- Histogram

// Histogram 是累积直方图（分桶累计计数 + 总和 + 总数）。
type Histogram struct {
	name    string
	help    string
	labels  string
	buckets []float64
	mu      sync.Mutex
	counts  []uint64 // 累积计数，长度 = len(buckets)+1（末位为 +Inf）
	sum     float64
	count   uint64
}

// NewHistogram 构造无标签直方图。buckets 为上界升序切片（不含 +Inf）；
// 传 nil 则使用 DefaultBuckets。
func NewHistogram(subsystem, metric, unit, help string, buckets []float64) *Histogram {
	bs := normalizeBuckets(buckets)
	return &Histogram{
		name:    newFamily("histogram", subsystem, metric, unit),
		help:    help,
		buckets: bs,
		counts:  make([]uint64, len(bs)+1),
	}
}

// Name 返回指标全名。
func (h *Histogram) Name() string { return h.name }

// Help 返回帮助文本。
func (h *Histogram) Help() string { return h.help }

// Type 返回 "histogram"。
func (h *Histogram) Type() string { return "histogram" }

// Observe 记录一次观测值。
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	h.sum += v
	// 找到第一个满足 v <= buckets[i] 的分桶，从该桶起（含 +Inf 桶）全部累加。
	idx := len(h.buckets)
	for i, ub := range h.buckets {
		if v <= ub {
			idx = i
			break
		}
	}
	for i := idx; i < len(h.counts); i++ {
		h.counts[i]++
	}
}

// WriteSamples 写出直方图样本：
//
//	name_bucket{le="..."} <累计计数>
//	name_sum <总和>
//	name_count <观测总数>
func (h *Histogram) WriteSamples(sb *strings.Builder) {
	h.mu.Lock()
	counts := append([]uint64(nil), h.counts...)
	sum := h.sum
	count := h.count
	h.mu.Unlock()

	for i, ub := range h.buckets {
		appendSample(sb, h.name+"_bucket",
			withExtraLabel(h.labels, "le", formatFloat(ub)), float64(counts[i]))
	}
	appendSample(sb, h.name+"_bucket",
		withExtraLabel(h.labels, "le", "+Inf"), float64(counts[len(h.buckets)]))
	appendSample(sb, h.name+"_sum", h.labels, sum)
	appendSample(sb, h.name+"_count", h.labels, float64(count))
}

// HistogramVec 是带标签的直方图族。
type HistogramVec struct {
	name       string
	help       string
	labelNames []string
	buckets    []float64
	mu         sync.RWMutex
	children   map[string]*Histogram
}

// NewHistogramVec 构造带标签直方图族。
func NewHistogramVec(subsystem, metric, unit, help string, buckets []float64, labelNames ...string) *HistogramVec {
	checkLabelNames(labelNames)
	return &HistogramVec{
		name:       newFamily("histogram", subsystem, metric, unit),
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		buckets:    normalizeBuckets(buckets),
		children:   make(map[string]*Histogram),
	}
}

// Name 返回指标全名。
func (v *HistogramVec) Name() string { return v.name }

// Help 返回帮助文本。
func (v *HistogramVec) Help() string { return v.help }

// Type 返回 "histogram"。
func (v *HistogramVec) Type() string { return "histogram" }

// WriteSamples 写出全部子样本。
func (v *HistogramVec) WriteSamples(sb *strings.Builder) {
	for _, k := range v.keys() {
		v.mu.RLock()
		h := v.children[k]
		v.mu.RUnlock()
		if h != nil {
			h.WriteSamples(sb)
		}
	}
}

// WithLabelValues 返回指定标签组合的直方图，不存在则创建。
func (v *HistogramVec) WithLabelValues(values ...string) (*Histogram, error) {
	key, err := v.keyOf(values)
	if err != nil {
		return nil, err
	}
	v.mu.RLock()
	h, ok := v.children[key]
	v.mu.RUnlock()
	if ok {
		return h, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if h, ok = v.children[key]; ok {
		return h, nil
	}
	h = &Histogram{
		name:    v.name,
		help:    v.help,
		labels:  key,
		buckets: v.buckets,
		counts:  make([]uint64, len(v.buckets)+1),
	}
	v.children[key] = h
	return h, nil
}

// MustWithLabelValues 是 WithLabelValues 的 panic 版本。
func (v *HistogramVec) MustWithLabelValues(values ...string) *Histogram {
	h, err := v.WithLabelValues(values...)
	if err != nil {
		panic("metrics: " + v.name + ": " + err.Error())
	}
	return h
}

// Delete 移除指定标签组合的子指标。
func (v *HistogramVec) Delete(values ...string) {
	key, err := v.keyOf(values)
	if err != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.children, key)
}

func (v *HistogramVec) keyOf(values []string) (string, error) {
	if len(values) != len(v.labelNames) {
		return "", fmt.Errorf("标签个数不匹配: 期望 %d 个 %v，实际 %d 个",
			len(v.labelNames), v.labelNames, len(values))
	}
	return renderLabels(v.labelNames, values), nil
}

func (v *HistogramVec) keys() []string {
	v.mu.RLock()
	keys := make([]string, 0, len(v.children))
	for k := range v.children {
		keys = append(keys, k)
	}
	v.mu.RUnlock()
	sortStrings(keys)
	return keys
}

// ---------------------------------------------------------------- helpers

// normalizeBuckets 校验并复制分桶：必须严格升序、不得包含 +Inf。
// 传 nil 时返回 DefaultBuckets 的副本。
func normalizeBuckets(b []float64) []float64 {
	if len(b) == 0 {
		return append([]float64(nil), DefaultBuckets...)
	}
	out := append([]float64(nil), b...)
	for i := 1; i < len(out); i++ {
		if out[i] <= out[i-1] {
			panic(fmt.Sprintf("metrics: 直方图分桶必须严格升序，索引 %d: %v", i, out))
		}
	}
	return out
}

// withExtraLabel 在既有标签串上追加一个标签。
// labels 形如 `{k="v"}` 或空串（无标签）。
func withExtraLabel(labels, key, value string) string {
	extra := key + `="` + escapeLabelValue(value) + `"`
	if labels == "" {
		return "{" + extra + "}"
	}
	return labels[:len(labels)-1] + "," + extra + "}"
}

// sortStrings 对字符串切片做原地插入排序。
// 标签集合规模通常在个位到十位量级，插入排序足够且避免引入额外依赖复杂度。
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
