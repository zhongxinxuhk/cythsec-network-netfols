package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/httpx"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{" debug ", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERR", slog.LevelError},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if err != nil {
			t.Fatalf("ParseLevel(%q) 意外错误: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseLevel(%q) 期望 %v，实际 %v", c.in, c.want, got)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("非法级别应报错")
	}
}

func TestNewRejectsBadFormat(t *testing.T) {
	if _, err := New(Options{Format: "xml"}); err == nil {
		t.Fatal("非法格式应报错")
	}
	if _, err := New(Options{Level: "verbose"}); err == nil {
		t.Fatal("非法级别应报错")
	}
}

// 关键验收：每行输出都必须能被 encoding/json 解析（对应清单中的「日志可被 jq 解析」）。
func TestJSONOutputParseable(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Options{Level: "debug", Format: "json", Service: "routerd", Output: &buf})
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}

	if _, err := New(Options{Level: "info", Format: "text", Output: &bytes.Buffer{}}); err != nil {
		t.Fatalf("text 格式应可用: %v", err)
	}

	l.Info("启动完成", "addr", ":8080")
	l.Debug("调试信息", "retry", 3)
	l.Warn("注意", "field", "值含引号\"与\\反斜杠")
	l.Error("失败", "err", "boom")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("期望 4 行日志，实际 %d 行:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v\n%s", i+1, err, line)
		}
		for _, key := range []string{"time", "level", "msg", "service"} {
			if _, ok := m[key]; !ok {
				t.Fatalf("第 %d 行缺少字段 %q: %s", i+1, key, line)
			}
		}
		if m["service"] != "routerd" {
			t.Fatalf("service 字段期望 routerd，实际 %v", m["service"])
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Options{Level: "warn", Format: "json", Output: &buf})
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	l.Info("应被过滤")
	l.Debug("应被过滤")
	l.Warn("应保留")

	out := buf.String()
	if strings.Contains(out, "应被过滤") {
		t.Fatalf("低于 warn 的日志不应输出:\n%s", out)
	}
	if !strings.Contains(out, "应保留") {
		t.Fatalf("warn 日志应输出:\n%s", out)
	}
}

func TestMiddlewareFields(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Options{Level: "info", Format: "json", Service: "routerd", Output: &buf})
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("12345"))
	})
	// 用 Route 声明模板，且模板与真实路径不同，以鉴别 route 与 path 两个字段。
	h := httpx.Chain(httpx.Route("/api/v1/routes/{id}", inner), Middleware(l))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/7", nil)
	req = req.WithContext(apiresp.WithRequestID(req.Context(), "req-abc"))
	req.RemoteAddr = "203.0.113.7:1234"
	h.ServeHTTP(httptest.NewRecorder(), req)

	fields := decodeSingleLine(t, buf.String())
	checks := map[string]any{
		"msg":        "http",
		"level":      "INFO",
		"service":    "routerd",
		"request_id": "req-abc",
		"method":     "POST",
		"route":      "/api/v1/routes/{id}", // 模板
		"path":       "/api/v1/routes/7",    // 真实路径
		"client_ip":  "203.0.113.7",
	}
	for k, want := range checks {
		if got := fields[k]; got != want {
			t.Errorf("字段 %q 期望 %v，实际 %v", k, want, got)
		}
	}
	if got := fields["status"]; got != float64(http.StatusCreated) {
		t.Errorf("status 期望 201，实际 %v", got)
	}
	if got := fields["bytes"]; got != float64(5) {
		t.Errorf("bytes 期望 5，实际 %v", got)
	}
	if _, ok := fields["duration_ms"]; !ok {
		t.Error("缺少 duration_ms 字段")
	}
}

func TestContextMiddleware(t *testing.T) {
	l, err := New(Options{Format: "json", Output: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}

	var got *slog.Logger
	var gotRID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = FromContext(r.Context())
		gotRID = apiresp.RequestIDFromContext(r.Context())
	})
	h := httpx.Chain(inner, ContextMiddleware(l))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(apiresp.WithRequestID(req.Context(), "rid-1"))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got == nil || got == slog.Default() {
		t.Fatal("上下文中的日志器应为注入的实例")
	}
	if gotRID != "rid-1" {
		t.Fatalf("request_id 期望 rid-1，实际 %q", gotRID)
	}
}

func TestFromContextDefault(t *testing.T) {
	if got := FromContext(context.Background()); got != slog.Default() {
		t.Fatal("无上下文日志器时应回退 slog.Default()")
	}
}

func decodeSingleLine(t *testing.T, s string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("期望 1 行日志，实际 %d 行:\n%s", len(lines), s)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("日志不是合法 JSON: %v\n%s", err, lines[0])
	}
	return m
}
