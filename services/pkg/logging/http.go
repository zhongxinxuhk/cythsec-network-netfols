// 本文件提供 HTTP 访问日志中间件。输出为结构化字段，可被 `jq` 直接解析。
package logging

import (
	"log/slog"
	"net/http"
	"time"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/httpx"
)

// Middleware 返回访问日志中间件，记录方法、路由、状态码、响应字节数与耗时。
//
// 字段说明：
//
//	method       请求方法
//	route        路由模板（优先）或请求路径
//	path         实际请求路径（便于定位未匹配路由的 404）
//	status       HTTP 状态码
//	bytes        响应体字节数
//	duration_ms  处理耗时（毫秒，float）
//	client_ip    客户端 IP（受 X-Forwarded-For 影响，仅可信代理解析）
//	request_id   请求追踪 ID（由 apiresp 上下文提供）
//
// 实现要点：中间件在调用 next 之前创建 RouteHolder 注入上下文，
// next 返回后再从同一承载器读取模板 —— 处理器写入的值才会被看见。
func Middleware(l *slog.Logger) func(http.Handler) http.Handler {
	if l == nil {
		l = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, holder := httpx.WithRouteHolder(r.Context())
			r = r.WithContext(ctx)

			start := time.Now()
			rec := httpx.NewStatusRecorder(w)

			next.ServeHTTP(rec, r)

			route := r.URL.Path
			if holder != nil {
				if tmpl := holder.Get(); tmpl != "" {
					route = tmpl
				}
			}

			l.LogAttrs(r.Context(), slog.LevelInfo, "http",
				slog.String("request_id", apiresp.RequestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.Status),
				slog.Int64("bytes", rec.Bytes),
				slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000.0),
				slog.String("client_ip", httpx.ClientIP(r)),
			)
		})
	}
}

// ContextMiddleware 把日志器注入请求上下文，使下层处理器可通过
// FromContext 取得带 request_id 等字段的子日志器。
func ContextMiddleware(l *slog.Logger) func(http.Handler) http.Handler {
	if l == nil {
		l = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub := l
			if rid := apiresp.RequestIDFromContext(r.Context()); rid != "" {
				sub = l.With(slog.String("request_id", rid))
			}
			next.ServeHTTP(w, r.WithContext(WithLogger(r.Context(), sub)))
		})
	}
}
