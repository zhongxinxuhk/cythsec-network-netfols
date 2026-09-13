package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusRecorderDefaultOK(t *testing.T) {
	rec := NewStatusRecorder(httptest.NewRecorder())
	if rec.Status != http.StatusOK {
		t.Fatalf("默认状态应为 200，实际 %d", rec.Status)
	}
	if _, err := rec.Write([]byte("abc")); err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	if rec.Status != http.StatusOK {
		t.Fatalf("未显式 WriteHeader 时状态应保持 200，实际 %d", rec.Status)
	}
	if rec.Bytes != 3 {
		t.Fatalf("字节数期望 3，实际 %d", rec.Bytes)
	}
	if !rec.WroteHeader {
		t.Fatal("Write 后 WroteHeader 应为 true")
	}
}

func TestStatusRecorderExplicitCode(t *testing.T) {
	rec := NewStatusRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusNotFound)
	if rec.Status != http.StatusNotFound {
		t.Fatalf("期望 404，实际 %d", rec.Status)
	}
	// 重复 WriteHeader 不应覆盖首次状态（与 net/http 语义一致）。
	rec.WriteHeader(http.StatusInternalServerError)
	if rec.Status != http.StatusNotFound {
		t.Fatalf("重复 WriteHeader 不应覆盖，实际 %d", rec.Status)
	}
}

func TestStatusRecorderAccumulatesBytes(t *testing.T) {
	rec := NewStatusRecorder(httptest.NewRecorder())
	for i := 0; i < 5; i++ {
		_, _ = rec.Write([]byte("ab"))
	}
	if rec.Bytes != 10 {
		t.Fatalf("字节数期望 10，实际 %d", rec.Bytes)
	}
}

func TestChainOrder(t *testing.T) {
	var order []string
	mw := func(tag string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, tag+"-in")
				next.ServeHTTP(w, r)
				order = append(order, tag+"-out")
			})
		}
	}
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}), mw("A"), mw("B"))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"A-in", "B-in", "handler", "B-out", "A-out"}
	if len(order) != len(want) {
		t.Fatalf("调用序列长度期望 %d，实际 %d: %v", len(want), len(order), order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("第 %d 步期望 %q，实际 %q（完整序列 %v）", i, want[i], order[i], order)
		}
	}
}

// 关键：模板与真实路径**必须不同**，否则测试无法鉴别「读到模板」与「回退路径」。
func TestRouteContext(t *testing.T) {
	const pattern = "/api/v1/policies/{id}"
	const realPath = "/api/v1/policies/42"

	var insideHandler string
	h := Route(pattern, func(w http.ResponseWriter, r *http.Request) {
		insideHandler = RouteLabel(r)
	})
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, realPath, nil))

	if insideHandler != pattern {
		t.Fatalf("处理器内路由标签期望模板 %q，实际 %q", pattern, insideHandler)
	}
	if insideHandler == realPath {
		t.Fatal("读取到的仍是真实路径 —— 路由模板未生效")
	}
}

// 中间件必须在 next 返回后仍能读到处理器写入的模板（共享承载器机制的核心断言）。
func TestRouteHolderVisibleToMiddleware(t *testing.T) {
	const pattern = "/api/v1/policies/{id}"
	const realPath = "/api/v1/policies/99"

	var afterNext string
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, holder := WithRouteHolder(r.Context())
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
			afterNext = holder.Get() // next 返回后读取
		})
	}

	h := Chain(Route(pattern, func(w http.ResponseWriter, r *http.Request) {
		// 处理器不显式写承载器，仅靠 Route 包装。
	}), mw)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, realPath, nil))

	if afterNext != pattern {
		t.Fatalf("中间件在 next 之后应读到模板 %q，实际 %q", pattern, afterNext)
	}
}

// 多层中间件应复用同一个承载器（幂等），避免内层创建新承载器导致外层读空。
func TestWithRouteHolderIsIdempotent(t *testing.T) {
	ctx1, h1 := WithRouteHolder(context.Background())
	ctx2, h2 := WithRouteHolder(ctx1)
	if h1 != h2 {
		t.Fatal("已存在承载器时应复用同一实例")
	}
	h1.Set("/pattern")
	if got := h2.Get(); got != "/pattern" {
		t.Fatalf("共享承载器读取失败，实际 %q", got)
	}
	_ = ctx2
}

func TestRouteLabelFallback(t *testing.T) {
	// 无承载器（未经过任何中间件与 Route 包装）时应回退路径。
	r := httptest.NewRequest(http.MethodGet, "/no/template", nil)
	if got := RouteLabel(r); got != "/no/template" {
		t.Fatalf("无承载器时应回退路径，实际 %q", got)
	}
	// 有承载器但未写入模板时同样回退路径。
	ctx, _ := WithRouteHolder(r.Context())
	r = r.WithContext(ctx)
	if got := RouteLabel(r); got != "/no/template" {
		t.Fatalf("承载器为空时应回退路径，实际 %q", got)
	}
}

func TestRouteHolderFromContextMissing(t *testing.T) {
	if h := RouteHolderFromContext(context.Background()); h != nil {
		t.Fatal("空上下文应返回 nil 承载器")
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{"仅 RemoteAddr", "192.0.2.10:5555", nil, "192.0.2.10"},
		{"XFF 单值", "192.0.2.10:5555", map[string]string{"X-Forwarded-For": "203.0.113.7"}, "203.0.113.7"},
		{"XFF 多值取首个", "192.0.2.10:5555", map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}, "203.0.113.7"},
		{"X-Real-IP", "192.0.2.10:5555", map[string]string{"X-Real-IP": "198.51.100.9"}, "198.51.100.9"},
		{"XFF 优先于 X-Real-IP", "192.0.2.10:5555", map[string]string{
			"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "198.51.100.9"}, "203.0.113.7"},
		{"RemoteAddr 无端口", "192.0.2.10", nil, "192.0.2.10"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remoteAddr
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			if got := ClientIP(r); got != c.want {
				t.Fatalf("期望 %q，实际 %q", c.want, got)
			}
		})
	}
}
