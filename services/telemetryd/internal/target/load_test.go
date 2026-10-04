package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemp 写入临时文件并返回路径。
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileValid(t *testing.T) {
	p := writeTemp(t, `{
	  "targets": [
	    {"name": "routerd", "url": "http://127.0.0.1:8080/metrics",
	     "interval_seconds": 15, "timeout_seconds": 10, "enabled": true,
	     "labels": {"env": "prod", "role": "control"}},
	    {"name": "policyd", "url": "http://127.0.0.1:8081/metrics", "enabled": false}
	  ]
	}`)

	targets, err := LoadFile(p, 0)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("目标数 = %d，期望 2", len(targets))
	}
	if targets[0].Name != "routerd" || !targets[0].Enabled {
		t.Errorf("第 1 个目标解析异常: %+v", targets[0])
	}
	if targets[0].Labels["env"] != "prod" {
		t.Errorf("标签未解析: %+v", targets[0].Labels)
	}
	if targets[1].Enabled {
		t.Error("enabled: false 未生效")
	}

	// 载入后应能直接进入 Store。
	st := NewStore()
	if err := st.Load(targets); err != nil {
		t.Fatalf("Store.Load: %v", err)
	}
	if got := len(st.Enabled()); got != 1 {
		t.Errorf("启用数 = %d，期望 1", got)
	}
}

// TestLoadFileAcceptsEmptyTargetList 固化一个刻意的宽松行为：
// targets 为空数组是合法的（表示「载入一个空配置」），不是错误。
func TestLoadFileAcceptsEmptyTargetList(t *testing.T) {
	targets, err := LoadFile(writeTemp(t, `{"targets":[]}`), 0)
	if err != nil {
		t.Fatalf("空列表不应报错: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("目标数 = %d，期望 0", len(targets))
	}
}

// TestLoadFileOmitsDefaults 固化「零值即默认」的语义：
// 未写 interval_seconds / timeout_seconds 的目标，解析后字段仍为零值，
// 生效值由 Interval() / Timeout() 按需计算 —— 而非在解析期被填成默认值。
func TestLoadFileOmitsDefaults(t *testing.T) {
	targets, err := LoadFile(writeTemp(t, `{"targets":[{"name":"x","url":"http://x.test/metrics"}]}`), 0)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if targets[0].IntervalSeconds != 0 || targets[0].TimeoutSeconds != 0 {
		t.Errorf("未配置的字段应保持零值: %+v", targets[0])
	}
	if targets[0].Interval().Seconds() != float64(DefaultIntervalSeconds) {
		t.Errorf("Interval() 应回落到默认 %ds", DefaultIntervalSeconds)
	}
}

func TestLoadFileRejectsMaxTargetsExceeded(t *testing.T) {
	p := writeTemp(t, `{"targets":[
	  {"name":"a","url":"http://a.test/metrics"},
	  {"name":"b","url":"http://b.test/metrics"},
	  {"name":"c","url":"http://c.test/metrics"}]}`)

	if _, err := LoadFile(p, 3); err != nil {
		t.Fatalf("等于上限应放行: %v", err)
	}
	_, err := LoadFile(p, 2)
	if err == nil {
		t.Fatal("超过上限应报错")
	}
	// 错误信息应指明实际数量与上限，便于运维定位。
	if !strings.Contains(err.Error(), "3") || !strings.Contains(err.Error(), "max_targets=2") {
		t.Errorf("错误信息未包含数量与上限: %v", err)
	}
}

// TestLoadFileRejectsUnknownFields 固化 DisallowUnknownFields 的意图：
// 字段名拼写错误必须报错，而不是被静默忽略 —— 把 interval_seconds 写成
// intervals_seconds 会静默退回默认间隔，是最难察觉的一类配置错误。
func TestLoadFileRejectsUnknownFields(t *testing.T) {
	if _, err := LoadFile(writeTemp(t, `{"targets":[{"name":"x","url":"http://x.test/"}],"exrtra":1}`), 0); err == nil {
		t.Error("顶层未知字段应报错")
	}
	if _, err := LoadFile(writeTemp(t, `{"targets":[{"name":"x","url":"http://x.test/","inteval_seconds":5}]}`), 0); err == nil {
		t.Error("目标层未知字段应报错（inteval_seconds 应为 interval_seconds）")
	}
}

func TestLoadFileRejectsMalformedJSON(t *testing.T) {
	for name, content := range map[string]string{
		"语法错误":   `{"targets":[{"name":"x"}`,
		"非 JSON": `这不是 JSON`,
		"空文件":    ``,
	} {
		if _, err := LoadFile(writeTemp(t, content), 0); err == nil {
			t.Errorf("%s 应报错", name)
		}
	}
}

// TestLoadFileMissingFileReportsPath 校验错误信息包含路径 ——
// 否则运维只知道「解析失败」却不知读的是哪个文件。
func TestLoadFileMissingFileReportsPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there.json")
	_, err := LoadFile(missing, 0)
	if err == nil {
		t.Fatal("文件不存在应报错")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("错误信息应包含文件路径 %q，实际: %v", missing, err)
	}
}

// TestLoadFileValidationHappensAtStoreLoad 明确职责边界：
// LoadFile 只做「解析 + 数量上限」，语义校验由 Store.Load 统一承担。
// 这样从文件载入与从 API 写入走的是同一条校验路径，不会出现两套规则。
func TestLoadFileValidationHappensAtStoreLoad(t *testing.T) {
	targets, err := LoadFile(writeTemp(t, `{"targets":[{"name":"x","url":"ftp://bad.test/"}]}`), 0)
	if err != nil {
		t.Fatalf("LoadFile 不应做 URL 语义校验: %v", err)
	}
	if err := NewStore().Load(targets); err == nil {
		t.Error("Store.Load 应拒绝非法 URL")
	}
}
