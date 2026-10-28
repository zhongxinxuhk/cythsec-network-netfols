// Package api 提供 routerd 的 HTTP 控制面 API。
// 供 Web Console 消费：获取系统信息、网卡/IP、路由表等。
//
// 横切关注点（三个基础端点、中间件栈、低基数路由标签）统一由
// cythsec/services/pkg/controlplane 提供，本包只注册 routerd 的业务路由。
//
// 中间件顺序（由外到内）：
//
//	request_id -> 访问日志 -> CORS -> 上下文日志 -> 指标 -> 路由处理器
//
// 日志与指标中间件各自在调用 next 之前注入 httpx.RouteHolder，使得请求结束后
// 仍能读到处理器声明的路由模板（低基数标签），而非具体路径。
package api

import (
	"context"
	"log/slog"
	"net/http"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/routerd/internal/netinfo"
	"cythsec/services/routerd/internal/networkcfg"
)

// ServiceName 是 routerd 在日志、健康检查与指标子系中使用的服务名。
const ServiceName = "routerd"

// ServerOptions 配置 routerd 控制面 HTTP 服务的行为。
//
// 所有字段均为可选：零值即使用默认行为，便于测试与最小化启动。
type ServerOptions struct {
	Access          *controlplane.Access
	NetworkConfig   *networkcfg.Store
	NetworkObserve  func(context.Context) (networkcfg.Observation, error)
	NetworkValidate func(context.Context, networkcfg.Config) (networkcfg.NativeValidation, error)
	// CORSAllowedOrigins 允许跨域的源列表；为空时使用默认 ["http://localhost:5173"]。
	// 支持特殊值 "*" 表示允许任意源（仅建议开发/演示环境使用）。
	CORSAllowedOrigins []string
	// Logger 结构化日志器；为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Metrics 聚合的 HTTP 指标；为 nil 时不采集 HTTP 指标。
	Metrics *metrics.HTTPMetrics
	// Registry 指标注册表；非 nil 时暴露 GET /metrics。
	Registry *metrics.Registry
	// RuntimeMetricsRefresh 由 metrics.RegisterGoCollector 返回，用于抓取前刷新运行时指标。
	RuntimeMetricsRefresh func()
	// DisableMetrics 显式关闭 /metrics 端点（优先级高于 Registry）。
	DisableMetrics bool
}

// RegisterRoutes 把 routerd 的业务路由注册到控制面 mux。
//
// 必须使用 controlplane.Handle（内部套 httpx.Route）：裸 mux.HandleFunc 会让
// route 标签退化为具体请求路径。
func RegisterRoutes(mux *http.ServeMux) {
	RegisterRoutesWithNetworkConfig(mux, nil)
}

func RegisterRoutesWithNetworkConfig(mux *http.ServeMux, store *networkcfg.Store) {
	registerRouterRoutes(mux, store, nil, nil)
}

func registerRouterRoutes(mux *http.ServeMux, store *networkcfg.Store, observe func(context.Context) (networkcfg.Observation, error), validate func(context.Context, networkcfg.Config) (networkcfg.NativeValidation, error)) {
	if observe == nil {
		observe = networkcfg.NewObserver().Capture
	}
	registerNetworkObservation(mux, observe)
	if validate == nil {
		validate = networkcfg.NewNativeValidator().Validate
	}
	registerNetworkValidation(mux, validate)
	registerNetworkConfig(mux, store)
	// v1 控制面 API（供 Web Console 对接）
	controlplane.Handle(mux, "GET /api/v1/system", handleSystem)
	controlplane.Handle(mux, "GET /api/v1/interfaces", handleInterfaces)
	controlplane.Handle(mux, "GET /api/v1/routes", handleRoutes)
	controlplane.Handle(mux, "GET /api/v1/traffic", handleTraffic)
}

// NewServer 构造 routerd 的 HTTP handler（供测试与嵌入使用）。
func NewServer(opts ServerOptions) http.Handler {
	return controlplane.NewHandler(controlplane.Options{
		Access:                opts.Access,
		Service:               ServiceName,
		CORSAllowedOrigins:    opts.CORSAllowedOrigins,
		Logger:                opts.Logger,
		Metrics:               opts.Metrics,
		Registry:              opts.Registry,
		RuntimeMetricsRefresh: opts.RuntimeMetricsRefresh,
		DisableMetrics:        opts.DisableMetrics,
	}, func(mux *http.ServeMux) {
		registerRouterRoutes(mux, opts.NetworkConfig, opts.NetworkObserve, opts.NetworkValidate)
	})
}

// handleSystem 处理 GET /api/v1/system，返回主机基础信息
// （hostname / os / arch / go_version / pid，见 netinfo.SystemInfo）。
// GetSystem 纯读本机信息、无错误返回，故恒为 200。
func handleSystem(w http.ResponseWriter, r *http.Request) {
	apiresp.JSON(w, r, http.StatusOK, netinfo.GetSystem())
}

// handleInterfaces 处理 GET /api/v1/interfaces，返回本机网络接口列表
// （名称、MAC、MTU、地址等，见 netinfo.InterfaceInfo）。
// 采集失败时返回 500 + CodeInternal。
func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := netinfo.ListInterfaces()
	if err != nil {
		apiresp.Err(w, r, http.StatusInternalServerError, apiresp.CodeInternal, err.Error())
		return
	}
	apiresp.JSON(w, r, http.StatusOK, ifaces)
}

// handleRoutes 处理 GET /api/v1/routes，返回内核路由表。
// 非 Linux 平台下 netinfo 返回空列表（不算错误）；仅采集失败时返回 500 + CodeInternal。
func handleRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := netinfo.ListRoutes()
	if err != nil {
		apiresp.Err(w, r, http.StatusInternalServerError, apiresp.CodeInternal, err.Error())
		return
	}
	apiresp.JSON(w, r, http.StatusOK, routes)
}

// handleTraffic 处理 GET /api/v1/traffic，返回各接口的收发计数。
// 非 Linux 平台下返回空列表；仅采集失败时返回 500 + CodeInternal。
func handleTraffic(w http.ResponseWriter, r *http.Request) {
	traf, err := netinfo.ListTraffic()
	if err != nil {
		apiresp.Err(w, r, http.StatusInternalServerError, apiresp.CodeInternal, err.Error())
		return
	}
	apiresp.JSON(w, r, http.StatusOK, traf)
}
