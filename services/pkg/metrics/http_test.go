package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cythsec/services/pkg/httpx"
)

func TestHTTPMetricsMiddleware(t *testing.T) {
	reg := NewRegistry()
	m, err := NewHTTPMetrics(reg)
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	if reg == nil {
		t.Fatal("registry 不应为 nil")
	}

	mux := http.NewServeMux()
	// 刻意让路由模板与真实路径不同，以鉴别「读到模板」与「回退路径」。
	mux.HandleFunc("GET /api/v1/items/{id}",
		httpx.Route("/api/v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello"))
		}))
	mux.HandleFunc("GET /boom", httpx.Route("/boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))

	h := m.Middleware(mux)

	// 两次 200（不同 id，但标签应归并到同一模板），一次 500。
	for _, p := range []string{"/api/v1/items/1", "/api/v1/items/2"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("期望 500，实际 %d", rec.Code)
	}

	out := reg.Text()

	// 两次不同 id 的请求必须归并到同一路由模板标签（低基数）。
	if !strings.Contains(out, `cythsec_http_requests_total{method="GET",route="/api/v1/items/{id}",status="200"} 2`) {
		t.Fatalf("路由模板未作为标签（或未归并 id）:\n%s", out)
	}
	if strings.Contains(out, `route="/api/v1/items/1"`) || strings.Contains(out, `route="/api/v1/items/2"`) {
		t.Fatalf("不应出现带具体 id 的高基数标签:\n%s", out)
	}
	if !strings.Contains(out, `cythsec_http_requests_total{method="GET",route="/boom",status="500"} 1`) {
		t.Fatalf("500 计数不符:\n%s", out)
	}
	// 直方图应记录 2 次观测。
	if !strings.Contains(out, `cythsec_http_request_duration_seconds_count{method="GET",route="/api/v1/items/{id}"} 2`) {
		t.Fatalf("直方图观测数不符:\n%s", out)
	}
	// 响应字节数应被记录（"hello" = 5 字节 × 2 = 10）。
	if !strings.Contains(out, `cythsec_http_response_size_bytes_sum{method="GET",route="/api/v1/items/{id}"} 10`) {
		t.Fatalf("响应字节数不符（期望 2×5=10）:\n%s", out)
	}
	// 在途请求应回落到 0。
	if !strings.Contains(out, "cythsec_http_requests_in_flight_count 0") {
		t.Fatalf("在途请求数应回到 0:\n%s", out)
	}
}

// 未注入路由模板时应回退为请求路径（兜底行为）。
func TestHTTPMetricsFallsBackToPath(t *testing.T) {
	reg := NewRegistry()
	m, _ := NewHTTPMetrics(reg)

	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/raw/path", nil))

	if !strings.Contains(reg.Text(), `route="/raw/path"`) {
		t.Fatalf("未注入路由模板时应回退路径:\n%s", reg.Text())
	}
}

func TestMetricsHandlerContentType(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(NewCounter("http", "requests", "total", "h"))

	refreshCalled := 0
	h := reg.Handler(func() { refreshCalled++ })

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if got, want := rec.Header().Get("Content-Type"), "text/plain; version=0.0.4; charset=utf-8"; got != want {
		t.Fatalf("Content-Type 期望 %q，实际 %q", want, got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rec.Code)
	}
	if refreshCalled != 1 {
		t.Fatalf("refresh 应被调用 1 次，实际 %d 次", refreshCalled)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# TYPE cythsec_http_requests_total counter") {
		t.Fatalf("/metrics 未输出指标:\n%s", body)
	}
}

func TestMetricsHandlerNilRefresh(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler(nil) // 不应 panic
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rec.Code)
	}
}

func TestRegisterGoCollector(t *testing.T) {
	reg := NewRegistry()
	refresh := RegisterGoCollector(reg)
	refresh()
	refresh() // 二次调用验证 NumGC 差值逻辑不产生负值

	out := reg.Text()
	for _, want := range []string{
		"# TYPE cythsec_go_goroutines_count gauge",
		"# TYPE cythsec_go_heap_alloc_bytes gauge",
		"# TYPE cythsec_go_gc_cycles_total counter",
		"cythsec_go_goroutines_count ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少 %q:\n%s", want, out)
		}
	}
	// goroutine 数应恒 ≥ 1（当前测试 goroutine）。
	if strings.Contains(out, "cythsec_go_goroutines_count 0") {
		t.Fatalf("goroutine 数不应为 0:\n%s", out)
	}
}
