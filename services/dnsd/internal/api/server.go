// Package api 提供 dnsd 的 HTTP 控制面 API。
//
// 基础端点（/healthz、/metrics、/api/v1/version）与中间件栈由
// cythsec/services/pkg/controlplane 统一提供，本包只注册区域相关路由：
//
//	GET /api/v1/zones            列出全部区域
//	GET /api/v1/zones/{name}     按区域名查询单个区域
//
// 区域名的路径参数允许包含点号（如 example.com.），Go 1.22 的 ServeMux
// 通配段可正确捕获；区域名在存储层统一规范化，故 Example.COM 与
// example.com. 命中同一区域。
package api

import (
	"log/slog"
	"net/http"

	"cythsec/services/dnsd/internal/dns"
	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
)

// ServiceName 是 dnsd 在日志、健康检查与指标子系中使用的服务名。
const ServiceName = "dnsd"

// ServerOptions 配置 dnsd 控制面 HTTP 服务的行为。
//
// 所有字段均为可选：零值即使用默认行为，便于测试与最小化启动。
type ServerOptions struct {
	// Store 是区域存储；为 nil 时使用一个空存储。
	Store *dns.Store
	// ZoneCount 是区域数仪表；为 nil 时不更新该指标。
	ZoneCount *metrics.Gauge
	// RecordCount 是记录数仪表；为 nil 时不更新该指标。
	RecordCount *metrics.Gauge
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

// ObservabilityMetrics 聚合 dnsd 自有的可观测性仪表。
type ObservabilityMetrics struct {
	ZoneCount   *metrics.Gauge
	RecordCount *metrics.Gauge
}

// NewMetrics 构造并登记 dnsd 自有指标。
//
// 指标名遵循 CYS-TEL-002 命名约定：
//
//	cythsec_dnsd_zones_entries    当前区域数
//	cythsec_dnsd_records_entries  当前资源记录数
func NewMetrics(reg *metrics.Registry) ObservabilityMetrics {
	zones := metrics.NewGauge("dnsd", "zones", "entries", "当前已加载的 DNS 区域数。")
	records := metrics.NewGauge("dnsd", "records", "entries", "当前已加载的资源记录总数。")
	if reg != nil {
		reg.MustRegister(zones)
		reg.MustRegister(records)
	}
	return ObservabilityMetrics{ZoneCount: zones, RecordCount: records}
}

// RegisterRoutes 把 dnsd 的业务路由注册到控制面 mux。
//
// 必须使用 controlplane.Handle（内部套 httpx.Route），使 route 保持为模板，
// 避免 /api/v1/zones/example.com. 之类路径把指标标签基数打散。
func RegisterRoutes(mux *http.ServeMux, opts ServerOptions) {
	controlplane.Handle(mux, "GET /api/v1/zones", listZones(opts))
	controlplane.Handle(mux, "GET /api/v1/zones/{name}", getZone(opts))
}

// NewServer 构造 dnsd 的 HTTP handler（供测试与嵌入使用）。
func NewServer(opts ServerOptions) http.Handler {
	if opts.Store == nil {
		opts.Store = dns.NewStore()
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

// listResponse 是区域列表的响应体。
type listResponse struct {
	Items []dns.Zone `json:"items"`
	Total int        `json:"total"`
}

// refreshGauges 同步自有仪表到存储当前状态。
//
// 在读取处刷新而非定时刷新：区域与记录数只在读/写区域时变化，定时轮询纯属
// 浪费；而 Prometheus 每次抓取 /metrics 都会触发一次读取，指标天然保持新鲜。
func refreshGauges(opts ServerOptions) {
	if opts.ZoneCount != nil {
		opts.ZoneCount.Set(float64(opts.Store.Count()))
	}
	if opts.RecordCount != nil {
		opts.RecordCount.Set(float64(opts.Store.RecordCount()))
	}
}

// listZones 返回全部区域。
func listZones(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items := opts.Store.List()
		refreshGauges(opts)
		apiresp.JSON(w, r, http.StatusOK, listResponse{Items: items, Total: len(items)})
	}
}

// getZone 按区域名返回单个区域。
//
// 区域名在路径中可能带结尾点（example.com.），因此不能依赖 CleanPath 之类
// 规范化；直接原样交给存储层（其自身会做大小写与结尾点规范化）。
func getZone(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		zone, ok := opts.Store.Get(name)
		if !ok {
			apiresp.Err(w, r, http.StatusNotFound, apiresp.CodeNotFound, "区域不存在: "+name)
			return
		}
		apiresp.JSON(w, r, http.StatusOK, zone)
	}
}
