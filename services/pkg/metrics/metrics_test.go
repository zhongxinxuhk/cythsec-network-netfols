package metrics

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------- naming

func TestValidateName(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		metric  string
		wantErr error
	}{
		{"合法 counter", "counter", "cythsec_http_requests_total", nil},
		{"合法 gauge", "gauge", "cythsec_routerd_routes_entries", nil},
		{"合法 histogram", "histogram", "cythsec_http_request_duration_seconds", nil},
		{"合法 gauge 速率", "gauge", "cythsec_routerd_traffic_bytes_per_second", nil},
		{"缺前缀", "counter", "http_requests_total", ErrBadPrefix},
		{"前缀错误", "counter", "cythsec2_http_requests_total", ErrBadPrefix},
		{"段数不足", "counter", "cythsec_http_total", ErrTooFewParts},
		{"子系未登记", "counter", "cythsec_foobar_requests_total", ErrBadSubsystem},
		{"counter 未以 _total 结尾", "counter", "cythsec_http_requests_count", ErrCounterTotal},
		{"gauge 以 _total 结尾", "gauge", "cythsec_http_requests_total", ErrGaugeTotal},
		{"单位未登记", "gauge", "cythsec_http_requests_furlongs", ErrBadUnit},
		{"首字符为数字", "counter", "cythsec_1http_requests_total", ErrBadCharset},
		{"含非法字符", "counter", "cythsec_http_requ-ests_total", ErrBadCharset},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateName(c.kind, c.metric)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("期望通过，实际报错: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望报错 %v，实际通过", c.wantErr)
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("期望错误 %v，实际 %v", c.wantErr, err)
			}
		})
	}
}

func TestBuildName(t *testing.T) {
	got, err := BuildName("routerd", "routes", "entries")
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	if want := "cythsec_routerd_routes_entries"; got != want {
		t.Fatalf("期望 %q，实际 %q", want, got)
	}

	if _, err := BuildName("routerd", "routes", "furlongs"); err == nil {
		t.Fatal("非法单位应报错")
	}
	if _, err := BuildName("routerd", "Routes", "entries"); err == nil {
		t.Fatal("大写字母应报错")
	}
}

func TestMustBuildNamePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustBuildName 对非法输入应 panic")
		}
	}()
	_ = MustBuildName("routerd", "routes", "furlongs")
}

// ---------------------------------------------------------------- escaping

func TestEscapeHelp(t *testing.T) {
	// 真实换行 -> 字面 `\n`；反斜杠 -> `\\`。
	in := "第一行\n第二行\\结尾"
	want := `第一行\n第二行\\结尾`
	if got := escapeHelp(in); got != want {
		t.Fatalf("期望 %q，实际 %q", want, got)
	}
	if got := escapeHelp("无特殊字符"); got != "无特殊字符" {
		t.Fatalf("无需转义时不应改动，实际 %q", got)
	}
}

func TestEscapeLabelValue(t *testing.T) {
	in := "a\"b\\c\nd"
	want := `a\"b\\c\nd`
	if got := escapeLabelValue(in); got != want {
		t.Fatalf("期望 %q，实际 %q", want, got)
	}
}

// ---------------------------------------------------------------- counter

func TestCounterVecRender(t *testing.T) {
	r := NewRegistry()
	c := NewCounterVec("http", "requests", "total", "HTTP 请求总数。", "method", "status")
	r.MustRegister(c)

	c.MustWithLabelValues("GET", "200").Add(3)
	c.MustWithLabelValues("POST", "500").Inc()

	want := strings.Join([]string{
		"# HELP cythsec_http_requests_total HTTP 请求总数。",
		"# TYPE cythsec_http_requests_total counter",
		`cythsec_http_requests_total{method="GET",status="200"} 3`,
		`cythsec_http_requests_total{method="POST",status="500"} 1`,
		"",
	}, "\n")

	if got := r.Text(); got != want {
		t.Fatalf("渲染不符\n--- 期望 ---\n%s\n--- 实际 ---\n%s", want, got)
	}
}

func TestCounterVecLabelMismatch(t *testing.T) {
	c := NewCounterVec("http", "requests", "total", "h", "method", "status")
	if _, err := c.WithLabelValues("GET"); err == nil {
		t.Fatal("标签个数不足应报错")
	}
	if _, err := c.WithLabelValues("GET", "200", "extra"); err == nil {
		t.Fatal("标签个数过多应报错")
	}
}

func TestCounterVecDelete(t *testing.T) {
	r := NewRegistry()
	c := NewCounterVec("http", "requests", "total", "h", "method")
	r.MustRegister(c)
	c.MustWithLabelValues("GET").Inc()
	c.MustWithLabelValues("POST").Inc()

	c.Delete("GET")
	got := r.Text()
	if strings.Contains(got, `method="GET"`) {
		t.Fatalf("删除后不应再出现 GET 标签:\n%s", got)
	}
	if !strings.Contains(got, `method="POST"`) {
		t.Fatalf("POST 标签应保留:\n%s", got)
	}
}

// ------------------------------------------------------------------ gauge

func TestGaugeArithmetic(t *testing.T) {
	g := NewGauge("http", "requests_in_flight", "count", "在途请求数。")
	if g.Value() != 0 {
		t.Fatalf("初始值应为 0，实际 %v", g.Value())
	}
	g.Inc()
	g.Inc()
	g.Dec()
	if got := g.Value(); got != 1 {
		t.Fatalf("期望 1，实际 %v", got)
	}
	g.Add(2.5)
	if got := g.Value(); got != 3.5 {
		t.Fatalf("期望 3.5，实际 %v", got)
	}
	g.Set(-1.25)
	if got := g.Value(); got != -1.25 {
		t.Fatalf("期望 -1.25，实际 %v", got)
	}
}

func TestGaugeNegativeRender(t *testing.T) {
	r := NewRegistry()
	g := NewGauge("go", "heap_alloc", "bytes", "堆内存。")
	r.MustRegister(g)
	g.Set(-0)
	if got := r.Text(); !strings.Contains(got, "cythsec_go_heap_alloc_bytes 0\n") {
		t.Fatalf("负零应渲染为 0:\n%s", got)
	}
}

// -------------------------------------------------------------- histogram

func TestHistogramRender(t *testing.T) {
	r := NewRegistry()
	h := NewHistogram("http", "request_duration", "seconds", "请求耗时。", []float64{0.1, 1})
	r.MustRegister(h)

	h.Observe(0.05) // <= 0.1
	h.Observe(0.5)  // <= 1
	h.Observe(2)    // +Inf

	want := strings.Join([]string{
		"# HELP cythsec_http_request_duration_seconds 请求耗时。",
		"# TYPE cythsec_http_request_duration_seconds histogram",
		`cythsec_http_request_duration_seconds_bucket{le="0.1"} 1`,
		`cythsec_http_request_duration_seconds_bucket{le="1"} 2`,
		`cythsec_http_request_duration_seconds_bucket{le="+Inf"} 3`,
		"cythsec_http_request_duration_seconds_sum 2.55",
		"cythsec_http_request_duration_seconds_count 3",
		"",
	}, "\n")

	if got := r.Text(); got != want {
		t.Fatalf("渲染不符\n--- 期望 ---\n%s\n--- 实际 ---\n%s", want, got)
	}
}

// 断言分桶计数单调不减（Prometheus 对累积直方图的硬性要求）。
func TestHistogramBucketsMonotonic(t *testing.T) {
	h := NewHistogram("http", "request_duration", "seconds", "h", []float64{0.01, 0.1, 1, 10})
	vals := []float64{0.001, 0.005, 0.05, 0.5, 5, 50, 0.02, 0.2}
	for _, v := range vals {
		h.Observe(v)
	}
	for i := 1; i < len(h.counts); i++ {
		if h.counts[i] < h.counts[i-1] {
			t.Fatalf("分桶 %d 计数 %d 小于前一分桶 %d，违反累积性", i, h.counts[i], h.counts[i-1])
		}
	}
	if h.counts[len(h.counts)-1] != uint64(len(vals)) {
		t.Fatalf("+Inf 桶应等于观测总数 %d，实际 %d", len(vals), h.counts[len(h.counts)-1])
	}
}

func TestHistogramWithLabels(t *testing.T) {
	r := NewRegistry()
	hv := NewHistogramVec("http", "response_size", "bytes", "响应体大小。",
		[]float64{100, 1000}, "method", "route")
	r.MustRegister(hv)
	hv.MustWithLabelValues("GET", "/healthz").Observe(50)
	hv.MustWithLabelValues("GET", "/healthz").Observe(500)

	got := r.Text()
	// 既有标签之后追加 le，且花括号闭合正确。
	if !strings.Contains(got, `cythsec_http_response_size_bytes_bucket{method="GET",route="/healthz",le="100"} 1`) {
		t.Fatalf("带标签的 bucket 行不符:\n%s", got)
	}
	if !strings.Contains(got, `cythsec_http_response_size_bytes_bucket{method="GET",route="/healthz",le="+Inf"} 2`) {
		t.Fatalf("带标签的 +Inf 桶不符:\n%s", got)
	}
	if !strings.Contains(got, `cythsec_http_response_size_bytes_sum{method="GET",route="/healthz"} 550`) {
		t.Fatalf("带标签的 sum 行不符:\n%s", got)
	}
}

func TestHistogramBucketValidation(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("非升序分桶应 panic")
		}
	}()
	_ = NewHistogram("http", "request_duration", "seconds", "h", []float64{1, 0.5})
}

func TestHistogramDefaultBuckets(t *testing.T) {
	h := NewHistogram("http", "request_duration", "seconds", "h", nil)
	if len(h.buckets) != len(DefaultBuckets) {
		t.Fatalf("应使用默认分桶 %d 个，实际 %d 个", len(DefaultBuckets), len(h.buckets))
	}
	// 确认是副本而非共享切片（避免调用方误改全局默认值）。
	h.buckets[0] = 999
	if DefaultBuckets[0] == 999 {
		t.Fatal("默认分桶被污染：normalizeBuckets 未复制")
	}
}

// ---------------------------------------------------------------- registry

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(NewCounter("http", "requests", "total", "h"))
	defer func() {
		if recover() == nil {
			t.Fatal("重复注册应 panic")
		}
	}()
	r.MustRegister(NewCounter("http", "requests", "total", "h"))
}

func TestRegistryRejectsBadName(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatal("非法命名应 panic")
		}
	}()
	// 直接构造一个绕开校验的 Collector 也应被 Registry 拦下。
	r.MustRegister(badCollector{})
}

type badCollector struct{}

func (badCollector) Name() string                     { return "not_prefixed_total" }
func (badCollector) Help() string                     { return "h" }
func (badCollector) Type() string                     { return "counter" }
func (badCollector) WriteSamples(sb *strings.Builder) {}

func TestRegistrySortedOutput(t *testing.T) {
	r := NewRegistry()
	// 故意乱序注册。
	r.MustRegister(NewGauge("routerd", "routes", "entries", "h"))
	r.MustRegister(NewCounter("http", "requests", "total", "h"))
	r.MustRegister(NewGauge("go", "heap_alloc", "bytes", "h"))

	names := r.Names()
	want := []string{
		"cythsec_go_heap_alloc_bytes",
		"cythsec_http_requests_total",
		"cythsec_routerd_routes_entries",
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("第 %d 个指标名期望 %q，实际 %q", i, want[i], names[i])
		}
	}

	// 输出中 HELP 行顺序应与排序一致。
	got := r.Text()
	iGo := strings.Index(got, "# HELP cythsec_go_heap_alloc_bytes")
	iHTTP := strings.Index(got, "# HELP cythsec_http_requests_total")
	iRTD := strings.Index(got, "# HELP cythsec_routerd_routes_entries")
	if !(iGo < iHTTP && iHTTP < iRTD) {
		t.Fatalf("HELP 行未按字典序排列: go=%d http=%d routerd=%d", iGo, iHTTP, iRTD)
	}
}

func TestRegistryUnregister(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(NewCounter("http", "requests", "total", "h"))
	if !r.Unregister("cythsec_http_requests_total") {
		t.Fatal("注销应成功")
	}
	if r.Unregister("cythsec_http_requests_total") {
		t.Fatal("重复注销应返回 false")
	}
	if strings.Contains(r.Text(), "cythsec_http_requests_total") {
		t.Fatal("注销后不应再输出该指标")
	}
}

func TestEmptyRegistryRendersEmpty(t *testing.T) {
	if got := NewRegistry().Text(); got != "" {
		t.Fatalf("空注册表应输出空串，实际 %q", got)
	}
}

// -------------------------------------------------------------- concurrency

// 并发增减必须无数据竞争（配合 -race 运行）。
func TestConcurrentUpdates(t *testing.T) {
	r := NewRegistry()
	c := NewCounterVec("http", "requests", "total", "h", "status")
	h := NewHistogramVec("http", "request_duration", "seconds", "h", nil, "route")
	g := NewGauge("http", "requests_in_flight", "count", "h")
	r.MustRegister(c, h, g)

	const goroutines = 16
	const iters = 200

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				c.MustWithLabelValues("200").Inc()
				h.MustWithLabelValues("/healthz").Observe(0.001)
				g.Inc()
				g.Dec()
				_ = r.Text() // 与写入并发读取
			}
		}(i)
	}
	wg.Wait()

	if got := c.MustWithLabelValues("200").Value(); got != goroutines*iters {
		t.Fatalf("计数期望 %d，实际 %d", goroutines*iters, got)
	}
	if got := g.Value(); got != 0 {
		t.Fatalf("在途计数应回到 0，实际 %v", got)
	}
}

func TestFormatFloat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{12, "12"},
		{2.55, "2.55"},
		{-3, "-3"},
		{0.001, "0.001"},
		{1e21, "1e+21"},
	}
	for _, c := range cases {
		if got := formatFloat(c.in); got != c.want {
			t.Fatalf("formatFloat(%v) 期望 %q，实际 %q", c.in, c.want, got)
		}
	}
	// 特殊值：用变量做除数以避免编译期常量除零错误。
	zero := 0.0
	if got := formatFloat(1.0 / zero); got != "+Inf" {
		t.Fatalf("+Inf 期望 \"+Inf\"，实际 %q", got)
	}
	if got := formatFloat(-1.0 / zero); got != "-Inf" {
		t.Fatalf("-Inf 期望 \"-Inf\"，实际 %q", got)
	}
	if got := formatFloat(zero / zero); got != "NaN" {
		t.Fatalf("NaN 期望 \"NaN\"，实际 %q", got)
	}
}

func TestWithExtraLabel(t *testing.T) {
	if got := withExtraLabel("", "le", "0.1"); got != `{le="0.1"}` {
		t.Fatalf("无标签时期望 {le=\"0.1\"}，实际 %q", got)
	}
	if got := withExtraLabel(`{a="b"}`, "le", "+Inf"); got != `{a="b",le="+Inf"}` {
		t.Fatalf("有标签时追加错误，实际 %q", got)
	}
}
