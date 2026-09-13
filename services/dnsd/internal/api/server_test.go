package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cythsec/services/dnsd/internal/dns"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
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
func newTestServer(t *testing.T, zones ...dns.Zone) (http.Handler, *dns.Store) {
	t.Helper()
	store := dns.NewStore()
	if err := store.Load(zones); err != nil {
		t.Fatalf("载入测试区域失败: %v", err)
	}

	var obs ObservabilityMetrics
	rt, err := controlplane.NewRuntime(controlplane.ServerConfig{
		Service:        ServiceName,
		LogLevel:       "error",
		LogFormat:      "json",
		MetricsEnabled: true,
		Logger:         discardLogger(),
		RegisterMetrics: func(reg *metrics.Registry) error {
			obs = NewMetrics(reg)
			return nil
		},
	}, func(mux *http.ServeMux) {
		RegisterRoutes(mux, ServerOptions{
			Store:       store,
			ZoneCount:   obs.ZoneCount,
			RecordCount: obs.RecordCount,
		})
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt.Handler, store
}

// envelope 是 apiresp 的统一响应信封。
type envelope struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
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
	if health.Service != "dnsd" {
		t.Errorf("/healthz service = %q，期望 dnsd", health.Service)
	}
}

func TestListZones(t *testing.T) {
	h, _ := newTestServer(t,
		dns.Zone{Name: "example.com", Records: []dns.Record{{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"}}},
		dns.Zone{Name: "other.test"},
	)

	rec := do(h, http.MethodGet, "/api/v1/zones")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", rec.Code)
	}
	var got struct {
		Items []dns.Zone `json:"items"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(decode(t, rec).Data, &got); err != nil {
		t.Fatalf("解析 data 失败: %v", err)
	}
	if got.Total != 2 || len(got.Items) != 2 {
		t.Fatalf("total=%d items=%d，期望 2/2", got.Total, len(got.Items))
	}
	if got.Items[0].Name != "example.com." {
		t.Errorf("应保持插入顺序且区域名已规范化，首条 = %q", got.Items[0].Name)
	}
	if got.Items[0].Records[0].Value != "192.0.2.1" {
		t.Errorf("记录内容不符: %+v", got.Items[0].Records)
	}
}

// TestGetZoneAcceptsEquivalentSpellings 是控制面语义的关键契约：
// 与存储层一致，路径参数的大小写与结尾点差异应命中同一区域。
func TestGetZoneAcceptsEquivalentSpellings(t *testing.T) {
	h, _ := newTestServer(t, dns.Zone{Name: "example.com"})

	for _, p := range []string{
		"/api/v1/zones/example.com",
		"/api/v1/zones/example.com.",
		"/api/v1/zones/EXAMPLE.COM",
	} {
		rec := do(h, http.MethodGet, p)
		if rec.Code != http.StatusOK {
			t.Errorf("%s 状态码 = %d，期望 200", p, rec.Code)
			continue
		}
		var z dns.Zone
		if err := json.Unmarshal(decode(t, rec).Data, &z); err != nil {
			t.Fatal(err)
		}
		if z.Name != "example.com." {
			t.Errorf("%s 返回区域名 %q，期望 example.com.", p, z.Name)
		}
	}
}

func TestGetZoneMissing(t *testing.T) {
	h, _ := newTestServer(t, dns.Zone{Name: "example.com"})

	// 未命中应为 404 且带业务错误码，而非 200 + 空对象。
	rec := do(h, http.MethodGet, "/api/v1/zones/nope.test")
	if rec.Code != http.StatusNotFound {
		t.Errorf("未命中状态码 = %d，期望 404", rec.Code)
	}
	if code := decode(t, rec).Code; code != 4004 {
		t.Errorf("业务码 = %d，期望 4004", code)
	}
}

// TestRouteLabelIsTemplate 校验路径参数（含点号的区域名）不会泄漏为指标标签。
func TestRouteLabelIsTemplate(t *testing.T) {
	h, _ := newTestServer(t,
		dns.Zone{Name: "a.example"},
		dns.Zone{Name: "b.example"},
	)

	do(h, http.MethodGet, "/api/v1/zones/a.example")
	do(h, http.MethodGet, "/api/v1/zones/b.example.")

	body := do(h, http.MethodGet, "/metrics").Body.String()

	if !strings.Contains(body, `route="/api/v1/zones/{name}"`) {
		t.Errorf("未以模板登记路由标签:\n%s", tail(body))
	}
	for _, leak := range []string{
		`route="/api/v1/zones/a.example"`,
		`route="/api/v1/zones/b.example."`,
	} {
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

// TestGaugesReflectStore 校验两个业务指标确实反映存储状态，
// 而不是永远为 0 的装饰性指标。
func TestGaugesReflectStore(t *testing.T) {
	h, store := newTestServer(t,
		dns.Zone{Name: "a.example", Records: []dns.Record{{Name: "www"}, {Name: "api"}}},
		dns.Zone{Name: "b.example", Records: []dns.Record{{Name: "www"}}},
	)

	// 读取一次触发指标刷新。
	do(h, http.MethodGet, "/api/v1/zones")
	body := do(h, http.MethodGet, "/metrics").Body.String()
	if !strings.Contains(body, "cythsec_dnsd_zones_entries 2") {
		t.Fatalf("区域数指标未反映当前值（期望 2）:\n%s", tail(body))
	}
	if !strings.Contains(body, "cythsec_dnsd_records_entries 3") {
		t.Fatalf("记录数指标未反映当前值（期望 3）:\n%s", tail(body))
	}

	// 存储变化后再次读取，指标应同步。
	if !store.Delete("b.example") {
		t.Fatal("删除失败")
	}
	do(h, http.MethodGet, "/api/v1/zones")
	body = do(h, http.MethodGet, "/metrics").Body.String()
	if !strings.Contains(body, "cythsec_dnsd_zones_entries 1") {
		t.Fatalf("区域数指标未随存储变化（期望 1）:\n%s", tail(body))
	}
	if !strings.Contains(body, "cythsec_dnsd_records_entries 2") {
		t.Fatalf("记录数指标未随存储变化（期望 2）:\n%s", tail(body))
	}
}

// TestNewServerEmbeddableContract 固化 NewServer 的嵌入契约：
// 未提供 Registry 时不暴露 /metrics，但仍提供 /healthz 与业务路由。
func TestNewServerEmbeddableContract(t *testing.T) {
	store := dns.NewStore()
	if err := store.Load([]dns.Zone{{Name: "x.example"}}); err != nil {
		t.Fatal(err)
	}
	h := NewServer(ServerOptions{Store: store, Logger: discardLogger()})

	if rec := do(h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d，期望 200", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/v1/zones"); rec.Code != http.StatusOK {
		t.Errorf("/api/v1/zones = %d，期望 200", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("未提供 Registry 时 /metrics 应为 404，实际 %d", rec.Code)
	}
}

// TestNewMetricsNamingConvention 校验指标名符合 CYS-TEL-002 命名约定。
//
// 直接对照 metrics.BuildName 的产物，而非硬编码字符串 —— 这样约定一旦演进，
// 本测试会随之跟进而不是变成过期的字面量断言。
func TestNewMetricsNamingConvention(t *testing.T) {
	obs := NewMetrics(metrics.NewRegistry())
	if obs.ZoneCount == nil || obs.RecordCount == nil {
		t.Fatal("应返回两个非 nil 仪表")
	}

	for _, c := range []struct{ got, subsystem, metric string }{
		{obs.ZoneCount.Name(), "dnsd", "zones"},
		{obs.RecordCount.Name(), "dnsd", "records"},
	} {
		want, err := metrics.BuildName(c.subsystem, c.metric, "entries")
		if err != nil {
			t.Fatalf("BuildName: %v", err)
		}
		if c.got != want {
			t.Errorf("指标名 = %q，期望 %q", c.got, want)
		}
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
