// Package controlplane 提供 cythsec 控制面各 Go 服务共用的 HTTP 装配骨架。
//
// 动机：routerd / policyd / dnsd / telemetryd 的横切关注点完全一致。若每服务
// 各写一份，四份实现会逐渐漂移 —— 而 CYS-TEL-002 要求「四服务统一暴露
// Prometheus 文本格式 /metrics」、CYS-RTD-002 要求统一结构化日志，靠复制粘贴
// 维持的「统一」并不可靠。把装配收敛到本包后，一致性由结构保证。
//
// 本包统一提供：
//
//   - 三个基础端点：GET /healthz、GET /metrics、GET /api/v1/version
//   - 一致的中间件栈（由外到内）：
//     request_id -> 访问日志 -> CORS -> 上下文日志 -> 指标 -> 路由
//   - 低基数路由标签（httpx.RouteHolder，模板写入 / 中间件读取）
//   - 统一的启动、就绪日志与 SIGINT/SIGTERM 优雅关闭
//
// 各服务只需通过 register 回调注册自己的业务路由。
//
// 本包只依赖标准库与仓库内部包。
package controlplane

import (
	"log/slog"
	"net/http"
	"strings"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/httpx"
	"cythsec/services/pkg/logging"
	"cythsec/services/pkg/metrics"
	"cythsec/services/pkg/versioninfo"
)

// DefaultCORSOrigins 是开发环境默认允许的跨域源（便于 Web Console 在 5173 联调）。
var DefaultCORSOrigins = []string{"http://localhost:5173"}

// Options 配置控制面 handler 的公共行为。
//
// 全部字段均为可选：零值即「无日志器、无指标、默认 CORS、默认服务名」，
// 便于最小化启动与单元测试。
type Options struct {
	Access *Access
	// Service 是服务名（如 "policyd"），写入 /healthz 响应与启动日志。
	Service string
	// CORSAllowedOrigins 允许跨域的源列表；为空时使用 DefaultCORSOrigins。
	// 支持特殊值 "*" 表示允许任意源（仅建议开发/演示环境使用）。
	CORSAllowedOrigins []string
	// Logger 结构化日志器；为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Metrics 聚合的 HTTP 指标；为 nil 时不采集 HTTP 指标。
	Metrics *metrics.HTTPMetrics
	// Registry 指标注册表；非 nil 且未禁用时暴露 GET /metrics。
	Registry *metrics.Registry
	// RuntimeMetricsRefresh 由 metrics.RegisterGoCollector 返回，抓取前刷新运行时指标。
	RuntimeMetricsRefresh func()
	// DisableMetrics 显式关闭 /metrics 端点（优先级高于 Registry）。
	DisableMetrics bool
}

// NewHandler 组装控制面 handler：基础端点 + register 回调注册的业务路由 + 中间件栈。
//
// register 为 nil 时只暴露三个基础端点。
//
// 注意：基础端点已占用 GET /healthz、GET /metrics、GET /api/v1/version 三个
// 模式，register 不得重复注册（http.ServeMux 会 panic，属期望的早失败）。
func NewHandler(opts Options, register func(mux *http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/session", httpx.Route("/api/v1/session", accessSession))

	mux.HandleFunc("GET /healthz", httpx.Route("/healthz", func(w http.ResponseWriter, r *http.Request) {
		apiresp.JSON(w, r, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": opts.Service,
		})
	}))

	// 版本端点（CYS-RTD-005）：版本、commit、构建时间、Go 版本。
	mux.HandleFunc("GET /api/v1/version", httpx.Route("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		apiresp.JSON(w, r, http.StatusOK, versioninfo.Get())
	}))

	if register != nil {
		register(mux)
	}

	// Prometheus 指标端点（CYS-RTD-004 / CYS-TEL-002）。
	if opts.Registry != nil && !opts.DisableMetrics {
		mux.Handle("GET /metrics", opts.Registry.Handler(opts.RuntimeMetricsRefresh))
	}

	origins := opts.CORSAllowedOrigins
	if len(origins) == 0 {
		origins = DefaultCORSOrigins
	}

	// 请求经过顺序（由外到内）：
	//   request_id -> logging -> cors -> ctx-logging -> metrics -> mux
	//
	// 为什么 request_id 必须在最外层：logger 中间件在 next 返回后要从自己持有的
	// 请求里读取 request_id，而 request_id 中间件是通过 r.WithContext 向下传递的；
	// 若 logger 位于其外侧，看到的将是注入前的请求，request_id 恒为空串。
	var mws []func(http.Handler) http.Handler
	mws = append(mws, RequestIDMiddleware)
	mws = append(mws, logging.Middleware(opts.Logger))
	mws = append(mws, CORSMiddleware(origins))
	mws = append(mws, logging.ContextMiddleware(opts.Logger))
	if opts.Metrics != nil {
		mws = append(mws, opts.Metrics.Middleware)
	}
	mws = append(mws, opts.Access.middleware(opts.Service))
	return httpx.Chain(mux, mws...)
}

// Handle 在 mux 上注册业务路由，并自动把路由模板声明为低基数标签。
//
// 请优先使用本函数而非裸 mux.HandleFunc：若遗漏 httpx.Route 包装，日志与
// 指标的 route 标签会退化为**具体请求路径**，随路径参数（如
// /api/v1/zones/example.com、/api/v1/zones/other.org）无限增长，
// 最终拖垮指标存储。本函数把「做对」变成默认行为。
//
// pattern 采用 Go 1.22 的「METHOD /path」语法，如
// "GET /api/v1/zones/{name}"；写入标签的模板为去掉方法后的路径部分。
func Handle(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, httpx.Route(routeTemplate(pattern), h))
}

// routeTemplate 从 ServeMux 模式中提取路径模板（去掉可选的 "METHOD " 前缀）。
func routeTemplate(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		return strings.TrimSpace(pattern[i+1:])
	}
	return pattern
}

// RequestIDMiddleware 为每个请求生成或复用 X-Request-ID，并写入响应头与上下文。
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = apiresp.NewRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(apiresp.WithRequestID(r.Context(), id)))
	})
}

// CORSMiddleware 处理跨域：对允许的源设置 CORS 响应头，并直接应答 OPTIONS 预检。
func CORSMiddleware(allowed []string) func(http.Handler) http.Handler {
	allowAll := false
	for _, o := range allowed {
		if o == "*" {
			allowAll = true
			break
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && (allowAll || originAllowed(origin, allowed)) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID, Authorization")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// originAllowed 判断 origin 是否在允许列表中（精确匹配）。
func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}
