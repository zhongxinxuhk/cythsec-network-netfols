// 本文件定义 cythsec 指标命名约定（CYS-TEL-002）。
//
// 约定：cythsec_<子系>_<指标>_<单位>
//
// 三段后缀各有明确语义，便于在 Grafana 里按正则批量筛选，也避免出现
// `cythsec_foo` / `cythsec_bar_total` 这类无单位、无归属的散乱命名。
//
// 示例：
//
//	cythsec_http_requests_total                 计数器（单位=total）
//	cythsec_http_request_duration_seconds       直方图（单位=seconds）
//	cythsec_go_heap_alloc_bytes                 仪表（单位=bytes）
//	cythsec_routerd_routes_entries              仪表（单位=entries）
package metrics

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// NamePrefix 是所有 cythsec 指标名必须携带的前缀。
const NamePrefix = "cythsec"

// allowedSubsystems 是允许的子系名集合。
//
// 新增服务或子系统时须同步登记于此 —— 这是刻意的约束：子系名一旦散乱，
// 按前缀聚合将失效。
var allowedSubsystems = map[string]bool{
	"http":           true, // 通用 HTTP 服务指标
	"go":             true, // Go 运行时指标
	"routerd":        true,
	"policyd":        true,
	"dnsd":           true,
	"telemetryd":     true,
	"packet_engine":  true,
	"traffic_engine": true,
	"storage":        true,
	"console":        true,
	"ml":             true,
}

// allowedUnits 是允许的单位 / 量纲后缀集合。
//
// 采用「后缀即单位」的设计，使同一物理量的指标可直接比较与换算。
var allowedUnits = map[string]bool{
	"total":              true, // 单调递增累计量（仅 counter）
	"seconds":            true, // 时间（秒）
	"bytes":              true, // 字节数
	"packets":            true, // 报文数
	"count":              true, // 无量纲计数
	"entries":            true, // 条目数（表项 / 记录）
	"connections":        true, // 连接数
	"ratio":              true, // 0..1 比率
	"percent":            true, // 0..100 百分比
	"bytes_per_second":   true, // 吞吐
	"packets_per_second": true, // 包速率
	"info":               true, // 恒为 1 的信息型指标
	"timestamp_seconds":  true, // Unix 时间戳
}

// metricNameRE 是 Prometheus 对指标名的字符集要求。
var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// unitSuffixes 是 allowedUnits 的「按长度降序」切片，用于最长后缀匹配。
// 之所以需要长度降序：`timestamp_seconds` 与 `seconds`、`bytes_per_second` 与
// `second` 等互为后缀，必须优先匹配更长者。
var unitSuffixes = func() []string {
	out := make([]string, 0, len(allowedUnits))
	for k := range allowedUnits {
		out = append(out, k)
	}
	// 按长度降序做插入排序（集合规模十余项，无需引入 sort 依赖复杂度）。
	// 注意：等长单位之间顺序无关紧要 —— 等长字符串不可能互为真后缀。
	for i := 1; i < len(out); i++ {
		cur := out[i]
		j := i - 1
		for j >= 0 && len(out[j]) < len(cur) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = cur
	}
	return out
}()

// segmentRE 是单个命名段的字符集要求（小写字母起头，允许数字与下划线）。
var segmentRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// 校验失败原因（供调用方按需判断，测试亦据此断言）。
var (
	ErrBadPrefix    = errors.New("必须以下划线前缀 " + NamePrefix + "_ 开头")
	ErrBadCharset   = errors.New("含非法字符（允许 [a-zA-Z0-9_:]，首字符不可为数字）")
	ErrTooFewParts  = errors.New("至少需要 3 段：cythsec_<子系>_<指标>_<单位>")
	ErrBadSubsystem = errors.New("子系名不在登记表中")
	ErrBadUnit      = errors.New("单位后缀不在允许集合中")
	ErrCounterTotal = errors.New("counter 必须以 _total 结尾")
	ErrGaugeTotal   = errors.New("gauge / histogram 不得以 _total 结尾（累计量请用 counter）")
)

// ValidateName 校验指标名是否符合命名约定。
//
// kind 为 Prometheus 类型名（counter / gauge / histogram）。
// 返回的具体错误可用 errors.Is 与上方 Err* 变量比对。
//
// 单位匹配采用「最长后缀优先」：`bytes_per_second` 这类跨多段的单位不会被
// 误判为最后一段 `second`。
func ValidateName(kind, name string) error {
	if !metricNameRE.MatchString(name) {
		return ErrBadCharset
	}
	if !strings.HasPrefix(name, NamePrefix+"_") {
		return ErrBadPrefix
	}

	unit, ok := matchUnit(name)
	if !ok {
		return ErrBadUnit
	}
	// 去掉 `_<单位>` 后缀，剩余部分应为 `cythsec_<子系>_<指标>`。
	core := strings.TrimSuffix(name, "_"+unit)
	parts := strings.Split(strings.TrimPrefix(core, NamePrefix+"_"), "_")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ErrTooFewParts
	}

	subsystem := parts[0]
	if !segmentRE.MatchString(subsystem) {
		return ErrBadCharset
	}
	if !allowedSubsystems[subsystem] {
		return fmt.Errorf("%w: %q", ErrBadSubsystem, subsystem)
	}

	switch kind {
	case "counter":
		if unit != "total" {
			return ErrCounterTotal
		}
	case "gauge", "histogram":
		if unit == "total" {
			return ErrGaugeTotal
		}
	case "":
		// 未指定类型时跳过类型相关校验。
	default:
		return fmt.Errorf("未知指标类型: %q", kind)
	}
	return nil
}

// matchUnit 在指标名尾部按「最长后缀优先」匹配已登记的单位。
func matchUnit(name string) (string, bool) {
	for _, u := range unitSuffixes {
		if strings.HasSuffix(name, "_"+u) {
			return u, true
		}
	}
	return "", false
}

// BuildName 按约定拼接指标名并校验。
//
//	BuildName("routerd", "routes", "entries") -> "cythsec_routerd_routes_entries"
//
// 供指标定义处使用，把命名错误提前到编译期附近的启动阶段暴露。
func BuildName(subsystem, metric, unit string) (string, error) {
	for _, s := range []string{subsystem, metric, unit} {
		if !segmentRE.MatchString(s) {
			return "", fmt.Errorf("%w: %q", ErrBadCharset, s)
		}
	}
	name := NamePrefix + "_" + subsystem + "_" + metric + "_" + unit
	if !allowedSubsystems[subsystem] {
		return "", fmt.Errorf("%w: %q", ErrBadSubsystem, subsystem)
	}
	if !allowedUnits[unit] {
		return "", fmt.Errorf("%w: %q", ErrBadUnit, unit)
	}
	return name, nil
}

// MustBuildName 是 BuildName 的 panic 版本，用于包级变量初始化。
func MustBuildName(subsystem, metric, unit string) string {
	name, err := BuildName(subsystem, metric, unit)
	if err != nil {
		panic("metrics: " + err.Error())
	}
	return name
}

// Subsystems 返回登记在册的全部子系名（字典序，便于文档生成与测试）。
func Subsystems() []string {
	out := make([]string, 0, len(allowedSubsystems))
	for k := range allowedSubsystems {
		out = append(out, k)
	}
	// 简单插入排序：集合规模小，无需引入 sort 依赖复杂度。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Units 返回允许的全部单位后缀（字典序）。
func Units() []string {
	out := make([]string, 0, len(allowedUnits))
	for k := range allowedUnits {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
