// Package api 提供 policyd 的 HTTP 控制面 API。
//
// 基础端点（/healthz、/metrics、/api/v1/version）与中间件栈由
// cythsec/services/pkg/controlplane 统一提供，本包只注册策略相关路由：
//
//	GET /api/v1/policies       列出全部策略规则
//	GET /api/v1/policies/{id}  查询单条策略规则
package api

import (
	"log/slog"
	"net/http"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/policyd/internal/policy"
)

// ServiceName 是 policyd 在日志、健康检查与指标子系中使用的服务名。
const ServiceName = "policyd"

// ServerOptions 配置 policyd 控制面 HTTP 服务的行为。
//
// 所有字段均为可选：零值即使用默认行为，便于测试与最小化启动。
type ServerOptions struct {
	// Store 是策略存储；为 nil 时使用一个空存储。
	Store *policy.Store
	// RuleCount 是策略条目数仪表；为 nil 时不更新该指标。
	RuleCount *metrics.Gauge
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

// NewRuleCountGauge 构造并登记「策略条目数」仪表。
//
// 指标名 cythsec_policyd_policies_entries，遵循 CYS-TEL-002 命名约定。
func NewRuleCountGauge(reg *metrics.Registry) *metrics.Gauge {
	g := metrics.NewGauge("policyd", "policies", "entries", "当前已加载的策略规则条数。")
	if reg != nil {
		reg.MustRegister(g)
	}
	return g
}

// RegisterRoutes 把 policyd 的业务路由注册到控制面 mux。
//
// 必须使用 controlplane.Handle（内部套 httpx.Route），使 route 保持为模板，
// 避免 /api/v1/policies/xxx 之类路径把指标标签基数打散。
func RegisterRoutes(mux *http.ServeMux, opts ServerOptions) {
	controlplane.Handle(mux, "GET /api/v1/policies", listPolicies(opts))
	controlplane.Handle(mux, "GET /api/v1/policies/{id}", getPolicy(opts))
}

// NewServer 构造 policyd 的 HTTP handler（供测试与嵌入使用）。
func NewServer(opts ServerOptions) http.Handler {
	if opts.Store == nil {
		opts.Store = policy.NewStore()
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

// listResponse 是策略列表的响应体。
type listResponse struct {
	Items []policy.Rule `json:"items"`
	Total int           `json:"total"`
}

// listPolicies 返回全部策略规则，并顺带刷新条目数仪表。
//
// 在读取处刷新而非定时刷新：条目数只在读/写策略时变化，定时轮询纯属浪费；
// 而 Prometheus 每次抓取 /metrics 都会触发一次读取，指标天然保持新鲜。
func listPolicies(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items := opts.Store.List()
		if opts.RuleCount != nil {
			opts.RuleCount.Set(float64(len(items)))
		}
		apiresp.JSON(w, r, http.StatusOK, listResponse{Items: items, Total: len(items)})
	}
}

// getPolicy 按 ID 返回单条策略规则。
func getPolicy(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rule, ok := opts.Store.Get(id)
		if !ok {
			apiresp.Err(w, r, http.StatusNotFound, apiresp.CodeNotFound, "策略规则不存在: "+id)
			return
		}
		apiresp.JSON(w, r, http.StatusOK, rule)
	}
}
