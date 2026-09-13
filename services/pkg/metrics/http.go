// 本文件提供 HTTP 服务的指标中间件与 /metrics 端点处理器。
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"cythsec/services/pkg/httpx"
)

// HTTPMetrics 聚合 HTTP 服务通用指标，供各服务复用。
//
// 指标清单（均遵循 cythsec_<子系>_<指标>_<单位> 约定）：
//
//	cythsec_http_requests_total{method,route,status}              counter
//	cythsec_http_request_duration_seconds{method,route}           histogram
//	cythsec_http_requests_in_flight_count                         gauge
//	cythsec_http_response_size_bytes{method,route}                histogram
type HTTPMetrics struct {
	Requests     *CounterVec
	Duration     *HistogramVec
	InFlight     *Gauge
	ResponseSize *HistogramVec
}

// NewHTTPMetrics 构造并注册 HTTP 通用指标。
//
// 返回值同时给出中间件，便于一行完成「注册 + 挂载」。
func NewHTTPMetrics(r *Registry) (*HTTPMetrics, error) {
	m := &HTTPMetrics{
		Requests: NewCounterVec("http", "requests", "total",
			"按方法 / 路由 / 状态码统计的 HTTP 请求总数。",
			"method", "route", "status"),
		Duration: NewHistogramVec("http", "request_duration", "seconds",
			"HTTP 请求处理耗时（秒）。",
			nil, "method", "route"),
		InFlight: NewGauge("http", "requests_in_flight", "count",
			"当前正在处理中的 HTTP 请求数。"),
		ResponseSize: NewHistogramVec("http", "response_size", "bytes",
			"HTTP 响应体字节数。",
			[]float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576}, "method", "route"),
	}
	if r != nil {
		r.MustRegister(m.Requests, m.Duration, m.InFlight, m.ResponseSize)
	}
	return m, nil
}

// Handler 返回 /metrics 端点处理器。
//
// refresh 可为 nil；非 nil 时每次抓取前调用一次，用于刷新运行时等瞬时指标。
func (r *Registry) Handler(refresh func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if refresh != nil {
			refresh()
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// 渲染失败只可能来自底层写入（如客户端断开），此时无法再改状态码，忽略即可。
		_ = r.WriteText(w)
	})
}

// Middleware 返回 HTTP 指标采集中间件。
//
// route 标签取自 httpx.RouteLabel：优先使用注册时声明的路由模板
// （低基数，推荐），缺失时回退请求路径。
//
// 实现要点：中间件在调用 next 之前创建 RouteHolder 注入上下文，
// next 返回后再从同一承载器读取模板 —— 处理器写入的值才会被看见。
func (m *HTTPMetrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, holder := httpx.WithRouteHolder(r.Context())
		r = r.WithContext(ctx)

		start := time.Now()
		m.InFlight.Inc()
		rec := httpx.NewStatusRecorder(w)

		next.ServeHTTP(rec, r)

		m.InFlight.Dec()
		route := routeOf(holder, r)
		method := r.Method

		m.Requests.MustWithLabelValues(method, route, strconv.Itoa(rec.Status)).Inc()
		m.Duration.MustWithLabelValues(method, route).Observe(time.Since(start).Seconds())
		m.ResponseSize.MustWithLabelValues(method, route).Observe(float64(rec.Bytes))
	})
}

// routeOf 取承载器中的路由模板；为空时回退请求路径。
func routeOf(holder *httpx.RouteHolder, r *http.Request) string {
	if holder != nil {
		if route := holder.Get(); route != "" {
			return route
		}
	}
	return r.URL.Path
}
