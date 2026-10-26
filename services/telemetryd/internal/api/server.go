// Package api 提供 telemetryd 的 HTTP 控制面 API。
//
// 基础端点（/healthz、/metrics、/api/v1/version）与中间件栈由
// cythsec/services/pkg/controlplane 统一提供，本包只注册抓取目标相关路由：
//
//	GET /api/v1/targets            列出全部抓取目标
//	GET /api/v1/targets/{name}     按名查询单个抓取目标
//
// 本骨架只做目标注册表的读写，实际抓取由 CYS-TEL-003 的调度器承担。
package api

import (
	"log/slog"
	"net/http"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/telemetryd/internal/aggregate"
	"cythsec/services/telemetryd/internal/target"
)

// ServiceName 是 telemetryd 在日志、健康检查与指标子系中使用的服务名。
const ServiceName = "telemetryd"

// ServerOptions 配置 telemetryd 控制面 HTTP 服务的行为。
//
// 所有字段均为可选：零值即使用默认行为，便于测试与最小化启动。
type ServerOptions struct {
	// Aggregates 是可选的本机聚合持久化存储；nil 时返回 503。
	Aggregates *aggregate.Store
	// Ingest 为可选磁盘队列写入器。
	Ingest *aggregate.Worker
	// Store 是抓取目标注册表；为 nil 时使用一个空注册表。
	Store *target.Store
	// TargetCount 是目标总数仪表；为 nil 时不更新该指标。
	TargetCount *metrics.Gauge
	// EnabledCount 是启用中目标数仪表；为 nil 时不更新该指标。
	EnabledCount *metrics.Gauge
	// CORSAllowedOrigins 允许跨域的源列表；为空时使用 controlplane 默认值。
	CORSAllowedOrigins []string
	// Logger 结构化日志器；为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Metrics 聚合的 HTTP 指标；为 nil 时不采集 HTTP 指标。
	Metrics *metrics.HTTPMetrics
	// Registry 指标注册表；非 nil 时暴露 GET /metrics。
	Registry *metrics.Registry
	// RuntimeMetricsRefresh 由 metrics.RegisterGoCollector 返回，抓取前刷新运行时指标。
	RuntimeMetricsRefresh func()
	// DisableMetrics 显式关闭 /metrics 端点（优先级高于 Registry）。
	DisableMetrics bool
}

// ObservabilityMetrics 聚合 telemetryd 自有的可观测性仪表。
type ObservabilityMetrics struct {
	TargetCount  *metrics.Gauge
	EnabledCount *metrics.Gauge
}

// NewMetrics 构造并登记 telemetryd 自有指标。
//
// 指标名遵循 CYS-TEL-002 命名约定：
//
//	cythsec_telemetryd_targets_entries        登记的抓取目标总数
//	cythsec_telemetryd_targets_enabled_count  其中处于启用状态的数量
func NewMetrics(reg *metrics.Registry) ObservabilityMetrics {
	total := metrics.NewGauge("telemetryd", "targets", "entries", "已登记的抓取目标总数。")
	enabled := metrics.NewGauge("telemetryd", "targets_enabled", "count", "处于启用状态的抓取目标数。")
	if reg != nil {
		reg.MustRegister(total)
		reg.MustRegister(enabled)
	}
	return ObservabilityMetrics{TargetCount: total, EnabledCount: enabled}
}

// RegisterRoutes 把 telemetryd 的业务路由注册到控制面 mux。
//
// 必须使用 controlplane.Handle（内部套 httpx.Route），使 route 保持为模板，
// 避免 /api/v1/targets/routerd 之类路径把指标标签基数打散。
func RegisterRoutes(mux *http.ServeMux, opts ServerOptions) {
	controlplane.Handle(mux, "GET /api/v1/analytics/ingest", ingestStatus(opts))
	controlplane.Handle(mux, "POST /api/v1/analytics/ingest", enqueueAggregate(opts))
	controlplane.Handle(mux, "GET /api/v1/analytics/imports", listImports(opts))
	controlplane.Handle(mux, "POST /api/v1/analytics/imports", importAggregates(opts))
	controlplane.Handle(mux, "GET /api/v1/analytics/imports/{id}", queryAggregates(opts))
	controlplane.Handle(mux, "GET /api/v1/targets", listTargets(opts))
	controlplane.Handle(mux, "GET /api/v1/targets/{name}", getTarget(opts))
}

// NewServer 构造 telemetryd 的 HTTP handler（供测试与嵌入使用）。
func NewServer(opts ServerOptions) http.Handler {
	if opts.Store == nil {
		opts.Store = target.NewStore()
	}
	return controlplane.NewHandler(controlplane.Options{
		Service:               ServiceName,
		CORSAllowedOrigins:    opts.CORSAllowedOrigins,
		Logger:                opts.Logger,
		Metrics:               opts.Metrics,
		Registry:              opts.Registry,
		RuntimeMetricsRefresh: opts.RuntimeMetricsRefresh,
		DisableMetrics:        opts.DisableMetrics,
	}, func(mux *http.ServeMux) { RegisterRoutes(mux, opts) })
}

// listResponse 是目标列表的响应体。
type listResponse struct {
	Items []target.Target `json:"items"`
	Total int             `json:"total"`
}

// refreshGauges 同步自有仪表到注册表当前状态。
//
// 在读取处刷新而非定时刷新：目标数只在读/写注册表时变化，定时轮询纯属
// 浪费；而 Prometheus 每次抓取 /metrics 都会触发一次读取，指标天然保持新鲜。
func refreshGauges(opts ServerOptions) {
	if opts.TargetCount != nil {
		opts.TargetCount.Set(float64(opts.Store.Count()))
	}
	if opts.EnabledCount != nil {
		opts.EnabledCount.Set(float64(len(opts.Store.Enabled())))
	}
}

// listTargets 返回全部抓取目标。
func listTargets(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items := opts.Store.List()
		refreshGauges(opts)
		apiresp.JSON(w, r, http.StatusOK, listResponse{Items: items, Total: len(items)})
	}
}

// getTarget 按名返回单个抓取目标。
func getTarget(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		t, ok := opts.Store.Get(name)
		if !ok {
			apiresp.Err(w, r, http.StatusNotFound, apiresp.CodeNotFound, "抓取目标不存在: "+name)
			return
		}
		apiresp.JSON(w, r, http.StatusOK, t)
	}
}
