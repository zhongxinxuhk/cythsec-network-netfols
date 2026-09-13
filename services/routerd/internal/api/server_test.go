package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer 构造测试用 handler（使用默认 CORS 源）。
func newTestServer() http.Handler {
	return NewServer(ServerOptions{})
}

// assertEnvelope 解码响应并校验业务码与 request_id 一致性。
func assertEnvelope(t *testing.T, w *httptest.ResponseRecorder, wantCode int) (code int, reqID string) {
	t.Helper()
	var env struct {
		Code      int             `json:"code"`
		RequestID string          `json:"request_id"`
		Data      json.RawMessage `json:"data"`
		Error     string          `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("解码响应失败: %v (body=%s)", err, w.Body.String())
	}
	if env.Code != wantCode {
		t.Errorf("code = %d, want %d", env.Code, wantCode)
	}
	if env.RequestID != w.Header().Get("X-Request-ID") {
		t.Errorf("envelope.request_id=%q 与响应头 X-Request-ID=%q 不一致",
			env.RequestID, w.Header().Get("X-Request-ID"))
	}
	return env.Code, env.RequestID
}

// TestHealthz 校验健康检查：200 / code=1000 / 复用 X-Request-ID / data.status=ok。
func TestHealthz(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "req-abc")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Request-ID"); got != "req-abc" {
		t.Errorf("X-Request-ID 头 = %q, want req-abc", got)
	}
	var env struct {
		Code      int               `json:"code"`
		RequestID string            `json:"request_id"`
		Data      map[string]string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if env.Code != 1000 {
		t.Errorf("code = %d, want 1000", env.Code)
	}
	if env.RequestID != "req-abc" {
		t.Errorf("request_id = %q, want req-abc", env.RequestID)
	}
	if env.Data["status"] != "ok" {
		t.Errorf("data.status = %q, want ok", env.Data["status"])
	}
}

// TestSystemData 校验 /api/v1/system 返回系统概貌且字段可解析。
func TestSystemData(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	assertEnvelope(t, w, 1000)
	var env struct {
		Data struct {
			Hostname  string `json:"hostname"`
			OS        string `json:"os"`
			Arch      string `json:"arch"`
			GoVersion string `json:"go_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if env.Data.Hostname == "" || env.Data.OS == "" || env.Data.Arch == "" {
		t.Errorf("system 字段缺失: %+v", env.Data)
	}
}

// TestCollectionEndpoints 校验 interfaces/routes/traffic 均返回 200 且 data 为数组。
// 注意：netinfo 在 macOS 上路由/流量返回空表，但接口枚举仍可用，测试跨平台通过。
func TestCollectionEndpoints(t *testing.T) {
	cases := []string{"/api/v1/interfaces", "/api/v1/routes", "/api/v1/traffic"}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			srv := newTestServer()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200", path, w.Code)
			}
			assertEnvelope(t, w, 1000)
			var env struct {
				Data []json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
				t.Fatalf("解码失败: %v", err)
			}
			// data 必须是数组（可能为空），不应为对象或 null。
			if env.Data == nil {
				t.Errorf("%s: data 不应为 null", path)
			}
		})
	}
}

// TestRequestIDGenerated 校验未提供 X-Request-ID 时自动生成。
func TestRequestIDGenerated(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Header().Get("X-Request-ID") == "" {
		t.Error("应自动生成 X-Request-ID")
	}
}

// TestCORSHeaders 校验允许的源能拿到 CORS 响应头。
func TestCORSHeaders(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want http://localhost:5173", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods 缺失")
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("Access-Control-Allow-Headers 缺失")
	}
}

// TestCORSDisallowForeignOrigin 校验非允许源不回写 ACAO（避免反射型信任）。
func TestCORSDisallowForeignOrigin(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("外来源不应回写 ACAO, got %q", got)
	}
}

// TestCORSPreflight 校验 OPTIONS 预检直接返回 204 并带 CORS 头。
func TestCORSPreflight(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/system", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("ACAO = %q", got)
	}
}

// TestMethodNotAllowed 校验对只读 GET 接口使用 POST 返回 405。
// Go 1.22 ServeMux 的方法模式匹配会自动返回 405，且仍贯穿中间件（带 request_id/cors）。
func TestMethodNotAllowed(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Error("405 也应带 X-Request-ID")
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("405 也应带 CORS 头, ACAO=%q", got)
	}
}
