package controlplane

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cythsec/services/pkg/apiresp"
)

// discardLogger 返回一个丢弃输出的 JSON 日志器，避免测试噪声。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(discardWriter{}, nil))
}

// discardWriter 丢弃全部写入。
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// envelope 是 apiresp 的统一响应信封（仅取测试关心的字段）。
type envelope struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}

// decodeEnvelope 解析响应体为信封。
func decodeEnvelope(t *testing.T, body []byte) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("响应不是合法 JSON: %v\n%s", err, body)
	}
	return env
}

func TestNewHandlerBaseEndpoints(t *testing.T) {
	rt, err := NewRuntime(ServerConfig{
		Service:        "policyd",
		LogLevel:       "error",
		LogFormat:      "json",
		MetricsEnabled: true,
		Logger:         discardLogger(),
	}, nil)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	// --- /healthz：应含 status 与 service ---
	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz 状态码 = %d，期望 200", rec.Code)
	}
	var health struct {
		Status  string `json:"status"`
		Service string `json:"service"`
	}
	if err := json.Unmarshal(decodeEnvelope(t, rec.Body.Bytes()).Data, &health); err != nil {
		t.Fatalf("解析 /healthz data 失败: %v", err)
	}
	if health.Status != "ok" {
		t.Errorf("status = %q，期望 ok", health.Status)
	}
	if health.Service != "policyd" {
		t.Errorf("service = %q，期望 policyd", health.Service)
	}

	// --- /api/v1/version：CYS-RTD-005 四个必填字段 ---
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/version 状态码 = %d，期望 200", rec.Code)
	}
	var ver map[string]any
	if err := json.Unmarshal(decodeEnvelope(t, rec.Body.Bytes()).Data, &ver); err != nil {
		t.Fatalf("解析 version data 失败: %v", err)
	}
	for _, k := range []string{"version", "commit", "build_time", "go_version"} {
		if _, ok := ver[k]; !ok {
			t.Errorf("版本端点缺少字段 %q，实际字段: %v", k, ver)
		}
	}

	// --- /metrics：Content-Type 必须符合文本暴露格式 ---
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics 状态码 = %d，期望 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("/metrics Content-Type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# TYPE cythsec_http_requests_total counter") {
		t.Errorf("/metrics 缺少 HTTP 请求计数族:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE cythsec_go_heap_alloc_bytes gauge") {
		t.Errorf("/metrics 缺少 Go 运行时指标族:\n%s", body)
	}
}

func TestNewHandlerRegistersBusinessRoutes(t *testing.T) {
	rt, err := NewRuntime(ServerConfig{
		Service:        "dnsd",
		LogLevel:       "error",
		MetricsEnabled: true,
		Logger:         discardLogger(),
	}, func(mux *http.ServeMux) {
		// 用 controlplane.Handle 而非裸 mux.HandleFunc —— 前者自动声明路由模板。
		Handle(mux, "GET /api/v1/zones/{name}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("业务路由状态码 = %d，期望 200", rec.Code)
	}

	// 带路径参数的路由必须以「模板」登记为低基数标签，而非具体路径。
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `route="/api/v1/zones/{name}"`) {
		t.Errorf("路径参数路由未以模板形式登记:\n%s", tail(rec.Body.String()))
	}
	if strings.Contains(rec.Body.String(), `route="/api/v1/zones/example.com"`) {
		t.Error("具体路径泄漏为指标标签，会造成基数膨胀")
	}
}

func TestRouteTemplate(t *testing.T) {
	cases := map[string]string{
		"GET /healthz":              "/healthz",
		"POST /api/v1/policies":     "/api/v1/policies",
		"/bare/path":                "/bare/path",
		"GET /api/v1/zones/{name}":  "/api/v1/zones/{name}",
		"DELETE /api/v1/rules/{id}": "/api/v1/rules/{id}",
	}
	for in, want := range cases {
		if got := routeTemplate(in); got != want {
			t.Errorf("routeTemplate(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestBareHandleFuncLeaksPath 固化一个刻意反例：不经 controlplane.Handle 注册的
// 处理器会把自己的**具体请求路径**写成指标标签，证明该辅助函数不是装饰性 API，
// 而是防止指标基数膨胀的必要约束。
func TestBareHandleFuncLeaksPath(t *testing.T) {
	rt, err := NewRuntime(ServerConfig{
		Service:        "dnsd",
		LogLevel:       "error",
		MetricsEnabled: true,
		Logger:         discardLogger(),
	}, func(mux *http.ServeMux) {
		// 反例：裸注册，未声明路由模板。
		mux.HandleFunc("GET /api/v1/bare/{name}", func(w http.ResponseWriter, r *http.Request) {})
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	rt.Handler.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/bare/alpha", nil))

	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `route="/api/v1/bare/alpha"`) {
		t.Error("预期裸注册会泄漏具体路径（若本断言失败，说明实现已能自动推断模板，" +
			"此时可移除本反例测试并简化 API）")
	}
}

func TestNewHandlerDisableMetrics(t *testing.T) {
	rt, err := NewRuntime(ServerConfig{
		Service:        "telemetryd",
		LogLevel:       "error",
		MetricsEnabled: false, // 显式关闭
		Logger:         discardLogger(),
	}, nil)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/metrics 应返回 404，实际 %d", rec.Code)
	}
}

func TestCORSMiddleware(t *testing.T) {
	handler := CORSMiddleware([]string{"http://allowed.test"})(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	// 允许的源应回显该源。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "http://allowed.test")
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://allowed.test" {
		t.Errorf("允许源的 ACAO = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q，期望 Origin", got)
	}

	// 非允许的源不应回显。
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "http://evil.test")
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("非允许源不应返回 ACAO，实际 %q", got)
	}

	// OPTIONS 预检应直接 204，不进入下游。
	reached := false
	preflight := CORSMiddleware([]string{"*"})(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { reached = true }))
	rec = httptest.NewRecorder()
	preflight.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/x", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("预检状态码 = %d，期望 204", rec.Code)
	}
	if reached {
		t.Error("预检不应进入下游处理器")
	}

	// 通配 "*" 允许任意源。
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "http://anything.test")
	CORSMiddleware([]string{"*"})(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://anything.test" {
		t.Errorf("通配源的 ACAO = %q", got)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	var seen string
	handler := RequestIDMiddleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seen = apiresp.RequestIDFromContext(r.Context())
		}))

	// 未携带时自动生成。
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if seen == "" {
		t.Error("未生成 request id")
	}
	if got := rec.Header().Get("X-Request-ID"); got != seen {
		t.Errorf("响应头 X-Request-ID = %q，上下文为 %q", got, seen)
	}

	// 已携带时原样复用。
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Request-ID", "caller-supplied")
	handler.ServeHTTP(rec, req)
	if seen != "caller-supplied" {
		t.Errorf("应复用调用方的 request id，实际 %q", seen)
	}
}

func TestNewRuntimeRejectsBadLogOptions(t *testing.T) {
	if _, err := NewRuntime(ServerConfig{Service: "x", LogLevel: "nope"}, nil); err == nil {
		t.Error("非法日志级别应返回错误")
	}
	if _, err := NewRuntime(ServerConfig{Service: "x", LogFormat: "xml"}, nil); err == nil {
		t.Error("非法日志格式应返回错误")
	}
}

func TestDefaultCORSOriginsApplied(t *testing.T) {
	rt, err := NewRuntime(ServerConfig{
		Service:        "routerd",
		LogLevel:       "error",
		MetricsEnabled: true,
		Logger:         discardLogger(),
	}, nil)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	// 未配置时使用 DefaultCORSOrigins，应允许 5173 联调源。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", DefaultCORSOrigins[0])
	rt.Handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != DefaultCORSOrigins[0] {
		t.Errorf("默认 CORS 未生效，ACAO = %q", got)
	}
}

// tail 返回字符串末尾若干行，便于在失败信息中查看指标尾部。
func tail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 12 {
		lines = lines[len(lines)-12:]
	}
	return strings.Join(lines, "\n")
}
