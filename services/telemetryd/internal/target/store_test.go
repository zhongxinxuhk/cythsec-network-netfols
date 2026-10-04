package target

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestValidateAcceptsGoodTarget(t *testing.T) {
	cases := []Target{
		{Name: "routerd", URL: "http://127.0.0.1:8080/metrics", Enabled: true},
		{Name: "routerd", URL: "https://cythsec.example/metrics", IntervalSeconds: 30, TimeoutSeconds: 5},
		{Name: "routerd", URL: "http://[::1]:8080/metrics", Labels: map[string]string{"env": "prod"}},
	}
	for i, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("用例 %d 应通过校验，实际: %v", i, err)
		}
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		want   error
	}{
		{"空目标名", Target{Name: "", URL: "http://a.test/"}, ErrEmptyName},
		{"纯空白目标名", Target{Name: "   ", URL: "http://a.test/"}, ErrEmptyName},
		{"空地址", Target{Name: "x", URL: ""}, ErrInvalidURL},
		{"非 http scheme", Target{Name: "x", URL: "ftp://a.test/metrics"}, ErrInvalidURL},
		{"file scheme", Target{Name: "x", URL: "file:///etc/passwd"}, ErrInvalidURL},
		{"缺少主机名", Target{Name: "x", URL: "http:///metrics"}, ErrInvalidURL},
		{"无 scheme", Target{Name: "x", URL: "127.0.0.1:8080"}, ErrInvalidURL},
		{"负间隔", Target{Name: "x", URL: "http://a.test/", IntervalSeconds: -1}, ErrBadInterval},
		{"负超时", Target{Name: "x", URL: "http://a.test/", TimeoutSeconds: -1}, ErrBadTimeout},
		{"空标签名", Target{
			Name: "x", URL: "http://a.test/", Labels: map[string]string{"": "v"},
		}, ErrBadLabelName},
	}
	for _, c := range cases {
		err := c.target.Validate()
		if !errors.Is(err, c.want) {
			t.Errorf("%s: 错误 = %v，期望 %v", c.name, err, c.want)
		}
	}
}

// TestValidateTimeoutMustBeLessThanInterval 固化一条真实的运维约束：
// 超时必须严格小于间隔。相等也非法 —— 一次卡在超时边界上的响应会与下一次
// 抓取首尾相接，长期看把实际抓取周期拉长一倍却不报错。
func TestValidateTimeoutMustBeLessThanInterval(t *testing.T) {
	// 显式设置且相等 -> 拒绝。
	err := Target{Name: "x", URL: "http://a.test/", IntervalSeconds: 10, TimeoutSeconds: 10}.Validate()
	if !errors.Is(err, ErrTimeoutTooBig) {
		t.Errorf("超时等于间隔应被拒绝，实际: %v", err)
	}
	// 超时大于间隔 -> 拒绝。
	err = Target{Name: "x", URL: "http://a.test/", IntervalSeconds: 5, TimeoutSeconds: 30}.Validate()
	if !errors.Is(err, ErrTimeoutTooBig) {
		t.Errorf("超时大于间隔应被拒绝，实际: %v", err)
	}
	// 超时小于间隔 -> 放行。
	if err := (Target{Name: "x", URL: "http://a.test/", IntervalSeconds: 30, TimeoutSeconds: 5}).Validate(); err != nil {
		t.Errorf("超时小于间隔应放行，实际: %v", err)
	}

	// 关键边界：默认值之间也必须自洽（10s < 15s）。
	// 若有人调大 DefaultTimeoutSeconds 而不动 DefaultIntervalSeconds，
	// 所有未显式配置的目标都会变非法 —— 此断言就是那道防线。
	if err := (Target{Name: "x", URL: "http://a.test/"}).Validate(); err != nil {
		t.Errorf("使用默认值的目标必须合法，实际: %v", err)
	}
	if DefaultTimeoutSeconds >= DefaultIntervalSeconds {
		t.Fatalf("默认超时 %ds 必须小于默认间隔 %ds",
			DefaultTimeoutSeconds, DefaultIntervalSeconds)
	}
}

func TestEffectiveDefaults(t *testing.T) {
	// 零值应取默认。
	z := Target{Name: "x", URL: "http://a.test/"}
	if z.Interval() != 15*time.Second {
		t.Errorf("Interval() = %v，期望 15s", z.Interval())
	}
	if z.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v，期望 10s", z.Timeout())
	}

	// 显式值应生效。
	e := Target{Name: "x", URL: "http://a.test/", IntervalSeconds: 60, TimeoutSeconds: 3}
	if e.Interval() != time.Minute {
		t.Errorf("Interval() = %v，期望 1m", e.Interval())
	}
	if e.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v，期望 3s", e.Timeout())
	}
}

func TestStorePutGetDelete(t *testing.T) {
	s := NewStore()

	if got := s.Count(); got != 0 {
		t.Fatalf("初始目标数 = %d，期望 0", got)
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("空注册表不应查到任何目标")
	}

	isNew, err := s.Put(Target{Name: "routerd", URL: "http://127.0.0.1:8080/metrics", Enabled: true})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !isNew {
		t.Error("首次写入应报告 isNew=true")
	}

	// 覆盖写不应新增条目。
	isNew, err = s.Put(Target{Name: "routerd", URL: "http://127.0.0.1:9090/metrics", Enabled: false})
	if err != nil {
		t.Fatalf("Put(覆盖): %v", err)
	}
	if isNew {
		t.Error("覆盖写应报告 isNew=false")
	}
	if got := s.Count(); got != 1 {
		t.Errorf("覆盖后目标数 = %d，期望 1", got)
	}

	got, ok := s.Get("routerd")
	if !ok {
		t.Fatal("应能查到 routerd")
	}
	if got.URL != "http://127.0.0.1:9090/metrics" || got.Enabled {
		t.Errorf("覆盖未生效: %+v", got)
	}

	if !s.Delete("routerd") {
		t.Error("删除已存在条目应返回 true")
	}
	if s.Delete("routerd") {
		t.Error("重复删除应返回 false")
	}
	if got := s.Count(); got != 0 {
		t.Errorf("删除后目标数 = %d，期望 0", got)
	}
}

// TestStorePutNormalizesAndRejects 校验名称规整与校验前置：
// 被拒绝的写入不得在注册表留下痕迹。
func TestStorePutNormalizesAndRejects(t *testing.T) {
	s := NewStore()

	if _, err := s.Put(Target{Name: "  routerd  ", URL: "http://127.0.0.1:8080/metrics"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get("routerd"); !ok {
		t.Error("目标名的首尾空白应被规整")
	}

	// 非法目标不得入表。
	if _, err := s.Put(Target{Name: "bad", URL: "ftp://a.test/"}); !errors.Is(err, ErrInvalidURL) {
		t.Errorf("非法 URL 应返回 ErrInvalidURL，实际 %v", err)
	}
	if _, err := s.Put(Target{Name: "", URL: "http://a.test/"}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("空名应返回 ErrEmptyName，实际 %v", err)
	}
	if got := s.Count(); got != 1 {
		t.Errorf("被拒绝的写入不应留下条目，目标数 = %d", got)
	}
}

// TestStoreEnabledFilter 校验调度器实际抓取的集合只含启用项。
func TestStoreEnabledFilter(t *testing.T) {
	s := NewStore()
	for _, c := range []struct {
		name    string
		enabled bool
	}{
		{"a", true},
		{"b", false},
		{"c", true},
	} {
		if _, err := s.Put(Target{Name: c.name, URL: "http://" + c.name + ".test/metrics", Enabled: c.enabled}); err != nil {
			t.Fatal(err)
		}
	}

	enabled := s.Enabled()
	if len(enabled) != 2 {
		t.Fatalf("启用数 = %d，期望 2", len(enabled))
	}
	if enabled[0].Name != "a" || enabled[1].Name != "c" {
		t.Errorf("启用集合内容/顺序异常: %+v", enabled)
	}
	if got := s.Count(); got != 3 {
		t.Errorf("总数应仍为 3，实际 %d", got)
	}
}

func TestStoreListKeepsInsertOrder(t *testing.T) {
	s := NewStore()
	for _, name := range []string{"c", "a", "b"} {
		if _, err := s.Put(Target{Name: name, URL: "http://" + name + ".test/metrics"}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.List()
	want := []string{"c", "a", "b"}
	if len(got) != len(want) {
		t.Fatalf("目标数 = %d，期望 %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("第 %d 个 = %q，期望 %q（应保持插入顺序）", i, got[i].Name, want[i])
		}
	}

	// 删除中间一个后顺序应保持稳定。
	if !s.Delete("a") {
		t.Fatal("删除 a 失败")
	}
	got = s.List()
	if len(got) != 2 || got[0].Name != "c" || got[1].Name != "b" {
		t.Errorf("删除后顺序异常: %+v", got)
	}
}

// TestStoreDoesNotLeakLabels 校验标签表不被外部引用泄漏。
//
// map 是引用类型：若 Put/Get/List 不做复制，调用方改写返回的标签会静默
// 污染注册表内部状态，且因无并发写而难以复现。
func TestStoreDoesNotLeakLabels(t *testing.T) {
	s := NewStore()

	in := map[string]string{"env": "prod"}
	if _, err := s.Put(Target{Name: "routerd", URL: "http://127.0.0.1:8080/metrics", Labels: in}); err != nil {
		t.Fatal(err)
	}
	in["env"] = "被外部篡改"

	// Get 返回值改写。
	got, _ := s.Get("routerd")
	got.Labels["env"] = "被外部篡改"
	got.Labels["注入"] = "x"

	// List 返回值改写。
	for _, item := range s.List() {
		item.Labels["env"] = "被外部篡改"
	}

	fresh, _ := s.Get("routerd")
	if fresh.Labels["env"] != "prod" {
		t.Errorf("标签被外部修改污染: env=%q，期望 prod", fresh.Labels["env"])
	}
	if _, exists := fresh.Labels["注入"]; exists {
		t.Error("外部向返回值新增的标签进入了存储")
	}
}

func TestStoreLoadReplacesAll(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Target{Name: "old", URL: "http://old.test/metrics"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Load([]Target{
		{Name: "n1", URL: "http://n1.test/metrics", Enabled: true},
		{Name: "n2", URL: "http://n2.test/metrics"},
	}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.Count(); got != 2 {
		t.Errorf("目标数 = %d，期望 2", got)
	}
	if _, ok := s.Get("old"); ok {
		t.Error("Load 应全量替换，旧目标不应残留")
	}
	if got := s.Enabled(); len(got) != 1 || got[0].Name != "n1" {
		t.Errorf("Load 后启用集合异常: %+v", got)
	}
	if got := s.List(); got[0].Name != "n1" || got[1].Name != "n2" {
		t.Errorf("Load 后顺序异常: %+v", got)
	}
}

// TestStoreLoadRejectsBadInput 同时校验「先全量校验、后替换」的原子性。
func TestStoreLoadRejectsBadInput(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Target{Name: "keep", URL: "http://keep.test/metrics"}); err != nil {
		t.Fatal(err)
	}

	// 含非法 URL。
	if err := s.Load([]Target{
		{Name: "ok", URL: "http://ok.test/metrics"},
		{Name: "bad", URL: "ftp://bad.test/"},
	}); err == nil {
		t.Error("含非法 URL 应报错")
	}
	// 空名。
	if err := s.Load([]Target{{Name: "ok", URL: "http://ok.test/metrics"}, {Name: "", URL: "http://x.test/"}}); err == nil {
		t.Error("含空名应报错")
	}
	// 重复名（含规整后同名）。
	if err := s.Load([]Target{
		{Name: "dup", URL: "http://dup.test/metrics"},
		{Name: "  dup  ", URL: "http://dup2.test/metrics"},
	}); err == nil {
		t.Error("规整后重复的目标名应报错")
	}

	// 校验失败时不得破坏现有数据。
	if got := s.Count(); got != 1 {
		t.Errorf("校验失败后目标数 = %d，期望保持 1", got)
	}
	if _, ok := s.Get("keep"); !ok {
		t.Error("校验失败后原有目标应完好")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				name := string(rune('a'+n)) + "-" + string(rune('0'+j%10))
				if _, err := s.Put(Target{
					Name: name, URL: "http://" + name + ".test/metrics", Enabled: true,
					Labels: map[string]string{"worker": string(rune('a' + n))},
				}); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.List()
				_ = s.Enabled()
				_ = s.Count()
				_, _ = s.Get("a-0")
				_ = s.Delete("zzz-not-exist")
			}
		}()
	}
	wg.Wait()

	if got := s.Count(); got == 0 {
		t.Error("并发写入后不应为空")
	}
	// 全部写入的 Enabled 均为 true，启用集合应与总集合等大。
	if got, want := len(s.Enabled()), s.Count(); got != want {
		t.Errorf("启用数 %d 应等于总数 %d", got, want)
	}
}

func TestValidateURL(t *testing.T) {
	for _, ok := range []string{
		"http://127.0.0.1:8080/metrics",
		"https://cythsec.example/metrics",
		"http://[::1]:9090/metrics",
		"http://host",
	} {
		if err := ValidateURL(ok); err != nil {
			t.Errorf("ValidateURL(%q) 应通过，实际: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "   ", "ftp://host/x", "file:///etc/passwd", "http:///x", "127.0.0.1:8080",
		"://missing-scheme",
	} {
		if err := ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) 应报错", bad)
		}
	}
}
