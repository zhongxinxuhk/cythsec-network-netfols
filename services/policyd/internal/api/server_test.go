package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/policyd/internal/policy"
)

// discardLogger 返回丢弃输出的 JSON 日志器，避免测试噪声。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// newTestServer 按 main() 完全相同的装配路径构造 handler：
// controlplane.NewRuntime 负责日志 / 指标 / 中间件，本包只注册业务路由。
//
// 刻意不复用 NewServer：后者的 Registry 可为 nil（嵌入场景），会与生产路径
// 产生差异，导致测试无法覆盖 /metrics 等由 controlplane 装配的端点。
func newTestServer(t *testing.T, rules ...policy.Rule) (http.Handler, *policy.Store) {
	t.Helper()
	store := policy.NewStore()
	if err := store.Load(rules); err != nil {
		t.Fatalf("载入测试规则失败: %v", err)
	}

	var ruleCount *metrics.Gauge
	rt, err := controlplane.NewRuntime(controlplane.ServerConfig{
		Service:        ServiceName,
		LogLevel:       "error",
		LogFormat:      "json",
		MetricsEnabled: true,
		Logger:         discardLogger(),
		RegisterMetrics: func(reg *metrics.Registry) error {
			ruleCount = NewRuleCountGauge(reg)
			return nil
		},
	}, func(mux *http.ServeMux) {
		RegisterRoutes(mux, ServerOptions{Store: store, RuleCount: ruleCount})
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt.Handler, store
}

// envelope 是 apiresp 的统一响应信封。
//
// Error 只在失败响应里出现，测试据此断言错误文案 —— 错误文案是使用者判断
// 「配置没写对」还是「表名写错了」的唯一依据，因此值得被测试固定下来。
type envelope struct {
	Code  int             `json:"code"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

// do 发起请求并返回记录器。
func do(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// decode 解析信封。
func decode(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("响应不是合法 JSON: %v\n%s", err, rec.Body.String())
	}
	return env
}

func TestBaseEndpointsPresent(t *testing.T) {
	h, _ := newTestServer(t)

	// 三个基础端点由 controlplane 统一提供，必须存在于每个服务。
	for _, p := range []string{"/healthz", "/metrics", "/api/v1/version"} {
		rec := do(h, http.MethodGet, p)
		if rec.Code != http.StatusOK {
			t.Errorf("%s 状态码 = %d，期望 200", p, rec.Code)
		}
	}

	// /healthz 应报出本服务名。
	var health struct {
		Status  string `json:"status"`
		Service string `json:"service"`
	}
	if err := json.Unmarshal(decode(t, do(h, http.MethodGet, "/healthz")).Data, &health); err != nil {
		t.Fatal(err)
	}
	if health.Service != "policyd" {
		t.Errorf("/healthz service = %q，期望 policyd", health.Service)
	}
}

func TestListPolicies(t *testing.T) {
	h, _ := newTestServer(t,
		policy.Rule{ID: "r1", Name: "放行", Priority: 10, Enabled: true},
		policy.Rule{ID: "r2", Name: "阻断", Priority: 5, Enabled: true},
	)

	rec := do(h, http.MethodGet, "/api/v1/policies")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", rec.Code)
	}
	var got struct {
		Items []policy.Rule `json:"items"`
		Total int           `json:"total"`
	}
	if err := json.Unmarshal(decode(t, rec).Data, &got); err != nil {
		t.Fatalf("解析 data 失败: %v", err)
	}
	if got.Total != 2 || len(got.Items) != 2 {
		t.Fatalf("total=%d items=%d，期望 2/2", got.Total, len(got.Items))
	}
	if got.Items[0].ID != "r1" {
		t.Errorf("应保持插入顺序，首条 = %q", got.Items[0].ID)
	}
}

func TestGetPolicyFoundAndMissing(t *testing.T) {
	h, _ := newTestServer(t, policy.Rule{ID: "abc", Name: "示例", Priority: 1, Enabled: true})

	rec := do(h, http.MethodGet, "/api/v1/policies/abc")
	if rec.Code != http.StatusOK {
		t.Fatalf("命中时状态码 = %d，期望 200", rec.Code)
	}
	var rule policy.Rule
	if err := json.Unmarshal(decode(t, rec).Data, &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID != "abc" || rule.Name != "示例" {
		t.Errorf("规则内容不符: %+v", rule)
	}

	// 未命中应为 404 且带业务错误码，而非 200 + 空对象。
	rec = do(h, http.MethodGet, "/api/v1/policies/missing")
	if rec.Code != http.StatusNotFound {
		t.Errorf("未命中状态码 = %d，期望 404", rec.Code)
	}
	if code := decode(t, rec).Code; code != 4004 {
		t.Errorf("业务码 = %d，期望 4004", code)
	}
}

// TestRouteLabelIsTemplate 校验路径参数不会泄漏为指标标签（基数保护）。
func TestRouteLabelIsTemplate(t *testing.T) {
	h, _ := newTestServer(t, policy.Rule{ID: "abc"})

	// 用两个不同 ID 请求，标签仍应只有一条模板序列。
	do(h, http.MethodGet, "/api/v1/policies/abc")
	do(h, http.MethodGet, "/api/v1/policies/def")

	rec := do(h, http.MethodGet, "/metrics")
	body := rec.Body.String()

	if !strings.Contains(body, `route="/api/v1/policies/{id}"`) {
		t.Errorf("未以模板登记路由标签:\n%s", tail(body))
	}
	for _, leak := range []string{`route="/api/v1/policies/abc"`, `route="/api/v1/policies/def"`} {
		if strings.Contains(body, leak) {
			t.Errorf("具体路径泄漏为指标标签: %s", leak)
		}
	}
}

func TestHealthzAndMetricsDoNotRequireAuth(t *testing.T) {
	// 明确固化设计意图：本骨架无鉴权，/metrics 与 /healthz 均对外开放。
	// 若后续引入鉴权，本测试会失败并提醒同步更新部署文档与探针配置。
	h, _ := newTestServer(t)
	if rec := do(h, http.MethodGet, "/metrics"); rec.Code != http.StatusOK {
		t.Errorf("/metrics 应无需鉴权，实际 %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz 应无需鉴权，实际 %d", rec.Code)
	}
}

// TestRuleCountGaugeReflectsStore 校验业务指标确实反映存储状态，
// 而不是一个永远为 0 的装饰性指标。
func TestRuleCountGaugeReflectsStore(t *testing.T) {
	h, store := newTestServer(t,
		policy.Rule{ID: "r1"},
		policy.Rule{ID: "r2"},
	)

	// 读取一次触发指标刷新。
	do(h, http.MethodGet, "/api/v1/policies")
	body := do(h, http.MethodGet, "/metrics").Body.String()
	if !strings.Contains(body, "cythsec_policyd_policies_entries 2") {
		t.Fatalf("指标未反映当前条数（期望 2）:\n%s", tail(body))
	}

	// 存储变化后再次读取，指标应同步。
	if !store.Delete("r1") {
		t.Fatal("删除失败")
	}
	do(h, http.MethodGet, "/api/v1/policies")
	body = do(h, http.MethodGet, "/metrics").Body.String()
	if !strings.Contains(body, "cythsec_policyd_policies_entries 1") {
		t.Fatalf("指标未随存储变化（期望 1）:\n%s", tail(body))
	}
}

// TestNewServerEmbeddableContract 固化 NewServer 的嵌入契约：
// 未提供 Registry 时不暴露 /metrics，但仍提供 /healthz 与业务路由。
func TestNewServerEmbeddableContract(t *testing.T) {
	store := policy.NewStore()
	if err := store.Load([]policy.Rule{{ID: "x"}}); err != nil {
		t.Fatal(err)
	}
	h := NewServer(ServerOptions{Store: store, Logger: discardLogger()})

	if rec := do(h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d，期望 200", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/v1/policies"); rec.Code != http.StatusOK {
		t.Errorf("/api/v1/policies = %d，期望 200", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("未提供 Registry 时 /metrics 应为 404，实际 %d", rec.Code)
	}
}

// tail 返回末尾若干行，便于在失败信息中查看指标尾部。
func tail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 10 {
		lines = lines[len(lines)-10:]
	}
	return strings.Join(lines, "\n")
}
