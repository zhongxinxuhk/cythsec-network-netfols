package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cythsec/services/pkg/logging"
	"cythsec/services/pkg/metrics"
)

// newObservableServer 构造带完整可观测性（日志 + 指标 + /metrics 端点）的 handler。
func newObservableServer(t *testing.T) (http.Handler, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	refresh := metrics.RegisterGoCollector(reg)
	hm, err := metrics.NewHTTPMetrics(reg)
	if err != nil {
		t.Fatalf("构造 HTTP 指标失败: %v", err)
	}
	logger, err := newDiscardLogger()
	if err != nil {
		t.Fatalf("构造日志器失败: %v", err)
	}
	return NewServer(ServerOptions{
		Logger:                logger,
		Metrics:               hm,
		Registry:              reg,
		RuntimeMetricsRefresh: refresh,
	}), reg
}

// newDiscardLogger 返回一个丢弃输出的 JSON 日志器（避免测试噪声）。
func newDiscardLogger() (*slog.Logger, error) {
	return logging.New(logging.Options{
		Level:   "error",
		Format:  "json",
		Service: "routerd",
		Output:  discardWriter{},
	})
}

// TestMetricsEndpoint 校验 GET /metrics 返回合法 Prometheus 文本格式。
func TestMetricsEndpoint(t *testing.T) {
	srv, _ := newObservableServer(t)

	// 先制造一次真实请求，使 HTTP 指标有数据。
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := w.Body.String()

	// 必需的家族声明
	for _, want := range []string{
		"# TYPE cythsec_http_requests_total counter",
		"# TYPE cythsec_http_request_duration_seconds histogram",
		"# TYPE cythsec_http_requests_in_flight_count gauge",
		"# TYPE cythsec_go_goroutines_count gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics 缺少 %q", want)
		}
	}

	// 路由标签必须是模板（低基数），不能是空或具体路径。
	if !strings.Contains(body, `cythsec_http_requests_total{method="GET",route="/healthz",status="200"} 1`) {
		t.Errorf("未记录 /healthz 请求明细:\n%s", tail(body, 20))
	}

	// 每一行都必须符合文本格式：注释行以 # 开头，样本行为 name[{labels}] value。
	for i, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if line == "" {
			t.Errorf("第 %d 行为空行（文本格式不允许空行）", i+1)
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, " ") {
			t.Errorf("第 %d 行缺少值与分隔空格: %q", i+1, line)
			continue
		}
		// 最后一个空格之后必须是数值。
		idx := strings.LastIndexByte(line, ' ')
		if idx < 0 || idx == len(line)-1 {
			t.Errorf("第 %d 行格式不合法: %q", i+1, line)
		}
	}
}

// TestMetricsEndpointDisabled 校验 -no-metrics / 配置关闭后不再暴露端点。
func TestMetricsEndpointDisabled(t *testing.T) {
	reg := metrics.NewRegistry()
	hm, _ := metrics.NewHTTPMetrics(reg)
	srv := NewServer(ServerOptions{Metrics: hm, Registry: reg, DisableMetrics: true})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("关闭后 status = %d, want 404", w.Code)
	}
}

// TestMetricsEndpointAbsentWithoutRegistry 校验未提供 Registry 时不注册端点。
func TestMetricsEndpointAbsentWithoutRegistry(t *testing.T) {
	srv := NewServer(ServerOptions{})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestVersionEndpoint 校验 /api/v1/version 返回版本信息且字段齐全。
func TestVersionEndpoint(t *testing.T) {
	srv, _ := newObservableServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var env struct {
		Code int `json:"code"`
		Data struct {
			Version   string `json:"version"`
			Commit    string `json:"commit"`
			BuildTime string `json:"build_time"`
			GoVersion string `json:"go_version"`
			OS        string `json:"os"`
			Arch      string `json:"arch"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("解码失败: %v (body=%s)", err, w.Body.String())
	}
	if env.Code != 1000 {
		t.Errorf("code = %d, want 1000", env.Code)
	}
	d := env.Data
	if d.Version == "" || d.Commit == "" || d.BuildTime == "" {
		t.Errorf("版本字段缺失: %+v", d)
	}
	if !strings.HasPrefix(d.GoVersion, "go") {
		t.Errorf("go_version = %q", d.GoVersion)
	}
	if d.OS == "" || d.Arch == "" {
		t.Errorf("os/arch 缺失: %+v", d)
	}
}

// TestRouteLabelsAreTemplates 校验 server 注册的所有路由均以 httpx.Route 包装，
// 使指标标签为稳定的路由模板（低基数）而非具体请求路径。
func TestRouteLabelsAreTemplates(t *testing.T) {
	srv, reg := newObservableServer(t)
	for _, p := range []string{"/healthz", "/api/v1/system", "/api/v1/version"} {
		srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	body := reg.Text()
	for _, p := range []string{"/healthz", "/api/v1/system", "/api/v1/version"} {
		if !strings.Contains(body, `route="`+p+`"`) {
			t.Errorf("路由 %s 未以模板形式登记为指标标签:\n%s", p, tail(body, 15))
		}
	}
	if strings.Contains(body, `route=""`) {
		t.Errorf("出现空路由标签:\n%s", tail(body, 15))
	}
}

// TestHealthzStillEnveloped 确保改造后 envelope 语义未变（回归保护）。
func TestHealthzStillEnveloped(t *testing.T) {
	srv, _ := newObservableServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "obs-1")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var env struct {
		Code      int    `json:"code"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if env.Code != 1000 || env.RequestID != "obs-1" {
		t.Errorf("envelope 语义变化: %+v", env)
	}
}

// TestAccessLogCarriesRequestID 校验访问日志中的 request_id 已填充且与请求头一致。
//
// 这是一个对中间件顺序敏感的断言：若 logging 中间件被放在 request_id 中间件之外，
// request_id 将恒为空串，本测试即失败。
func TestAccessLogCarriesRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(logging.Options{
		Level: "debug", Format: "json", Service: "routerd", Output: &buf,
	})
	if err != nil {
		t.Fatalf("构造日志器失败: %v", err)
	}
	reg := metrics.NewRegistry()
	hm, _ := metrics.NewHTTPMetrics(reg)
	srv := NewServer(ServerOptions{Logger: logger, Metrics: hm, Registry: reg})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "trace-123")
	srv.ServeHTTP(httptest.NewRecorder(), req)

	var found bool
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("日志行不是合法 JSON: %v\n%s", err, line)
		}
		if m["msg"] != "http" {
			continue
		}
		found = true
		if got := m["request_id"]; got != "trace-123" {
			t.Errorf("访问日志 request_id = %v, want trace-123", got)
		}
		if got := m["route"]; got != "/healthz" {
			t.Errorf("访问日志 route = %v, want /healthz", got)
		}
	}
	if !found {
		t.Fatalf("未找到 msg=http 的访问日志行:\n%s", buf.String())
	}
}

// TestAccessLogRequestIDGenerated 校验未带请求头时日志里是自动生成的 ID（非空）。
func TestAccessLogRequestIDGenerated(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := logging.New(logging.Options{
		Level: "debug", Format: "json", Service: "routerd", Output: &buf,
	})
	srv := NewServer(ServerOptions{Logger: logger})

	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil || m["msg"] != "http" {
			continue
		}
		rid, _ := m["request_id"].(string)
		if rid == "" {
			t.Error("未提供请求头时 request_id 也应自动生成，不能为空")
		}
		if len(rid) != 32 {
			t.Errorf("自动生成的 request_id 长度期望 32（16 字节 hex），实际 %d: %q", len(rid), rid)
		}
		return
	}
	t.Fatalf("未找到访问日志行:\n%s", buf.String())
}

// discardWriter 丢弃全部写入。
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// tail 返回文本的最后 n 行，便于失败时输出关键片段。
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
