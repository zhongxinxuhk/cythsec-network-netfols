// Package httpx 提供 cythsec 各 Go 服务共享的 HTTP 工具。
//
// 目前包含：
//
//   - StatusRecorder：包装 http.ResponseWriter 以捕获实际写出的状态码与响应字节数，
//     供日志中间件与指标中间件复用（避免两个包各自实现一遍记录器）。
//   - Chain：按「由外到内」的顺序串联中间件的语法糖。
//   - 路由模板传递（RouteHolder / Route / RouteLabel）：把注册时的路由模板
//     （如 `/api/v1/policies/{id}`）作为低基数标签提供给日志与指标。
//   - ClientIP：从请求中提取客户端 IP（支持 X-Forwarded-For / X-Real-IP）。
//
// 关于路由模板的实现方式：Go 1.23 起可直接读取 http.Request.Pattern，但本仓库
// go.mod 声明 go 1.22 且 CI 使用 Go 1.22 工具链，故不依赖该字段。
//
// 也不能仅在处理器内用 r.WithContext 传递 —— 中间件持有的是「替换前」的请求，
// 请求结束后从自己的 r 里读不到处理器写入的值。因此改用**共享承载器**：
// 中间件在调用 next 之前创建 RouteHolder 并注入上下文，处理器把模板写入同一
// 承载器（指针共享），中间件在 next 返回后读取，双方看到同一份值。
//
// 本包只依赖标准库。
package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
)

// StatusRecorder 包装 http.ResponseWriter，记录状态码与写出字节数。
//
// 注意：仅实现了 http.ResponseWriter 基础接口，不实现 http.Flusher / Hijacker 等
// 可选接口。若未来有 SSE / WebSocket 处理器需要透传这些接口，需在此补充。
type StatusRecorder struct {
	http.ResponseWriter
	// Status 是实际写出的 HTTP 状态码；未显式调用 WriteHeader 时为 200。
	Status int
	// Bytes 是写出的响应体字节数。
	Bytes int64
	// WroteHeader 标记是否已写出响应头。
	WroteHeader bool
}

// NewStatusRecorder 构造一个状态记录器，默认状态码 200。
func NewStatusRecorder(w http.ResponseWriter) *StatusRecorder {
	return &StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
}

// WriteHeader 记录状态码后透传。重复调用只记录首次（与 net/http 语义一致）。
func (r *StatusRecorder) WriteHeader(code int) {
	if !r.WroteHeader {
		r.Status = code
		r.WroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write 记录字节数后透传；若尚未写出响应头，先补记 200。
func (r *StatusRecorder) Write(b []byte) (int, error) {
	if !r.WroteHeader {
		r.WroteHeader = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.Bytes += int64(n)
	return n, err
}

// Chain 按「由外到内」的顺序串联中间件：
// Chain(h, A, B) 等价于 A(B(h))，即请求依次经过 A、B。
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// RouteHolder 在单次请求内承载路由模板。
//
// 设计要点：它是一个指针，被中间件与处理器共享；处理器写入、中间件读取。
// 加锁是因为理论上处理器可能派生子 goroutine 后再写（如异步路由匹配），
// 成本可忽略而正确性有保障。
type RouteHolder struct {
	mu    sync.RWMutex
	route string
}

// Set 写入路由模板。
func (h *RouteHolder) Set(route string) {
	h.mu.Lock()
	h.route = route
	h.mu.Unlock()
}

// Get 读取路由模板；未写入时返回空串。
func (h *RouteHolder) Get() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.route
}

// routeHolderCtxKey 是承载器在上下文中的键类型。
type routeHolderCtxKey struct{}

// WithRouteHolder 把承载器放入上下文；若上下文中已有承载器则原样复用（幂等），
// 从而保证多层中间件共享同一个承载器。
func WithRouteHolder(ctx context.Context) (context.Context, *RouteHolder) {
	if h, ok := ctx.Value(routeHolderCtxKey{}).(*RouteHolder); ok && h != nil {
		return ctx, h
	}
	h := &RouteHolder{}
	return context.WithValue(ctx, routeHolderCtxKey{}, h), h
}

// RouteHolderFromContext 取回承载器；不存在时返回 nil。
func RouteHolderFromContext(ctx context.Context) *RouteHolder {
	if h, ok := ctx.Value(routeHolderCtxKey{}).(*RouteHolder); ok {
		return h
	}
	return nil
}

// Route 包装处理器并声明其路由模板（供日志与指标作为低基数标签使用）。
//
// 若上下文中已存在承载器（由中间件注入），模板写入该承载器；
// 否则自行创建一份并注入上下文，保证处理器内部也能读到模板。
func Route(pattern string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if holder := RouteHolderFromContext(r.Context()); holder != nil {
			holder.Set(pattern)
		} else {
			ctx, holder := WithRouteHolder(r.Context())
			holder.Set(pattern)
			r = r.WithContext(ctx)
		}
		h(w, r)
	}
}

// RouteLabel 返回路由标签：优先取承载器中的模板，缺失时回退为请求路径。
//
// 回退路径存在标签基数膨胀风险（如 /api/v1/policies/123、/124 ...），
// 因此仅作为未匹配路由（404/405）时的兜底。
func RouteLabel(r *http.Request) string {
	if holder := RouteHolderFromContext(r.Context()); holder != nil {
		if route := holder.Get(); route != "" {
			return route
		}
	}
	return r.URL.Path
}

// ClientIP 返回客户端 IP（不含端口）。
//
// 优先取 X-Forwarded-For 的首个地址，其次 X-Real-IP，最后回退 RemoteAddr。
// 注意：这两组头均可被客户端伪造，仅在可信反向代理之后使用时才应依赖。
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
