// Package metrics 提供 cythsec 各 Go 服务共享的指标采集与 Prometheus 文本格式暴露。
//
// 设计取舍：**不引入 prometheus/client_golang**。理由：
//
//  1. 仓库贯彻「零第三方依赖」原则（packet-engine / traffic-engine 亦如此），
//     服务侧保持 `GOPROXY=off` 下 `go build` 可跑通对离线构建至关重要。
//  2. Prometheus 文本暴露格式（version 0.0.4）本身极其简单，自研约 300 行即可覆盖
//     Counter / Gauge / Histogram 三类核心指标，且完全可控。
//
// 暴露的端点内容形如：
//
//	# HELP cythsec_http_requests_total 处理的 HTTP 请求总数。
//	# TYPE cythsec_http_requests_total counter
//	cythsec_http_requests_total{method="GET",route="/healthz",status="200"} 12
//
// 指标命名约定见 naming.go（CYS-TEL-002）。
package metrics

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Collector 是可被 Registry 采集的指标族。
//
// 实现者需自行保证并发安全：WriteSamples 可能在任意时刻被并发调用。
type Collector interface {
	// Name 返回指标全名（须满足 naming.go 中的命名约定）。
	Name() string
	// Help 返回帮助文本（单行；渲染时会做转义处理）。
	Help() string
	// Type 返回 Prometheus 类型名：counter / gauge / histogram。
	Type() string
	// WriteSamples 把该族的全部样本行写入 sb（不含 # HELP / # TYPE 行）。
	WriteSamples(sb *strings.Builder)
}

// Registry 持有若干指标族，并负责渲染为 Prometheus 文本格式。
//
// Registry 可安全并发使用。注册应在服务启动阶段完成；运行期仅做采样读取。
type Registry struct {
	mu   sync.RWMutex
	cols []Collector
	seen map[string]bool
}

// NewRegistry 构造一个空注册表。
func NewRegistry() *Registry {
	return &Registry{seen: make(map[string]bool)}
}

// MustRegister 注册指标族；名称重复或不合约定时 panic（属编程错误，应在启动期暴露）。
func (r *Registry) MustRegister(cs ...Collector) {
	for _, c := range cs {
		if c == nil {
			panic("metrics: 注册了 nil Collector")
		}
		name := c.Name()
		if err := ValidateName(c.Type(), name); err != nil {
			panic("metrics: 指标名不合约定 " + name + ": " + err.Error())
		}
		r.mu.Lock()
		if r.seen[name] {
			r.mu.Unlock()
			panic("metrics: 指标重复注册: " + name)
		}
		r.seen[name] = true
		r.cols = append(r.cols, c)
		r.mu.Unlock()
	}
}

// Unregister 注销指定名称的指标族（返回是否找到）。主要用于测试。
func (r *Registry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.cols {
		if c.Name() == name {
			r.cols = append(r.cols[:i], r.cols[i+1:]...)
			delete(r.seen, name)
			return true
		}
	}
	return false
}

// Names 返回已注册的全部指标名（字典序，便于测试断言）。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.cols))
	for _, c := range r.cols {
		out = append(out, c.Name())
	}
	sort.Strings(out)
	return out
}

// WriteText 按 Prometheus 文本格式（version 0.0.4）渲染全部指标。
//
// 指标族按名称字典序输出，保证同一状态下输出稳定（便于快照测试与 diff）。
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.RLock()
	cols := make([]Collector, len(r.cols))
	copy(cols, r.cols)
	r.mu.RUnlock()

	sort.SliceStable(cols, func(i, j int) bool { return cols[i].Name() < cols[j].Name() })

	var sb strings.Builder
	for _, c := range cols {
		sb.WriteString("# HELP ")
		sb.WriteString(c.Name())
		sb.WriteByte(' ')
		sb.WriteString(escapeHelp(c.Help()))
		sb.WriteByte('\n')
		sb.WriteString("# TYPE ")
		sb.WriteString(c.Name())
		sb.WriteByte(' ')
		sb.WriteString(c.Type())
		sb.WriteByte('\n')
		c.WriteSamples(&sb)
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// Text 返回渲染后的文本（便于测试与日志）。
func (r *Registry) Text() string {
	var sb strings.Builder
	// WriteText 的唯一错误来源是底层 writer；strings.Builder 不会失败。
	_ = r.WriteText(&sb)
	return sb.String()
}

// escapeHelp 按文本格式规范转义 HELP 文本：反斜杠与换行。
func escapeHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// escapeLabelValue 按文本格式规范转义标签值：反斜杠、双引号与换行。
func escapeLabelValue(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			sb.WriteString(`\\`)
		case '"':
			sb.WriteString(`\"`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// renderLabels 把已按序排列的「名值对」渲染为 `{k="v",...}`。
// 无标签时返回空串（调用方直接省略花括号）。
func renderLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i := range names {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(names[i])
		sb.WriteString(`="`)
		sb.WriteString(escapeLabelValue(values[i]))
		sb.WriteString(`"`)
	}
	sb.WriteByte('}')
	return sb.String()
}

// appendSample 写出 `name{labels} value` 一行。
func appendSample(sb *strings.Builder, name, labels string, value float64) {
	sb.WriteString(name)
	if labels != "" {
		sb.WriteString(labels)
	}
	sb.WriteByte(' ')
	sb.WriteString(formatFloat(value))
	sb.WriteByte('\n')
}

// formatFloat 按 Prometheus 文本格式要求格式化浮点数。
// 整数值输出为整数形式（如 `12` 而非 `12.0`）；±Inf/NaN 使用规范写法。
func formatFloat(v float64) string {
	switch {
	case v != v: // NaN
		return "NaN"
	case v > maxFloat:
		return "+Inf"
	case v < -maxFloat:
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// maxFloat 用于 Inf 判定（math.MaxFloat64 的常量形式，避免额外 import）。
const maxFloat = 1.7976931348623157e+308
