package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemp 写入临时文件并返回路径。
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "zones.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileValid(t *testing.T) {
	p := writeTemp(t, `{
	  "zones": [
	    {"name": "example.com", "records": [
	      {"name": "www", "type": "A", "ttl": 300, "value": "192.0.2.1"},
	      {"name": "@", "type": "MX", "ttl": 3600, "value": "mail.example.com."}
	    ]},
	    {"name": "other.test"}
	  ]
	}`)

	zones, err := LoadFile(p, 0)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("区域数 = %d，期望 2", len(zones))
	}
	if len(zones[0].Records) != 2 {
		t.Errorf("第 1 个区域记录数 = %d，期望 2", len(zones[0].Records))
	}
	if zones[0].Records[0].TTL != 300 {
		t.Errorf("TTL = %d，期望 300", zones[0].Records[0].TTL)
	}
	if zones[1].Name != "other.test" {
		t.Errorf("第 2 个区域名 = %q", zones[1].Name)
	}

	// 载入后交给 Store 时区域名才被规范化；LoadFile 只负责解析原文。
	st := NewStore()
	if err := st.Load(zones); err != nil {
		t.Fatalf("Store.Load: %v", err)
	}
	if _, ok := st.Get("EXAMPLE.com."); !ok {
		t.Error("经 LoadFile + Store.Load 后应能按规范化写法命中")
	}
}

// TestLoadFileAcceptsEmptyZoneList 固化一个刻意的宽松行为：
// zones 为空数组是合法的（表示「载入一个空配置」），不是错误。
func TestLoadFileAcceptsEmptyZoneList(t *testing.T) {
	zones, err := LoadFile(writeTemp(t, `{"zones":[]}`), 0)
	if err != nil {
		t.Fatalf("空列表不应报错: %v", err)
	}
	if len(zones) != 0 {
		t.Errorf("区域数 = %d，期望 0", len(zones))
	}
}

func TestLoadFileRejectsMaxZonesExceeded(t *testing.T) {
	p := writeTemp(t, `{"zones":[{"name":"a.test"},{"name":"b.test"},{"name":"c.test"}]}`)

	if _, err := LoadFile(p, 3); err != nil {
		t.Fatalf("等于上限应放行: %v", err)
	}
	_, err := LoadFile(p, 2)
	if err == nil {
		t.Fatal("超过上限应报错")
	}
	// 错误信息应指明实际数量与上限，便于运维定位。
	if !strings.Contains(err.Error(), "3") || !strings.Contains(err.Error(), "max_zones=2") {
		t.Errorf("错误信息未包含数量与上限: %v", err)
	}
}

// TestLoadFileRejectsUnknownFields 固化 DisallowUnknownFields 的意图：
// 字段名拼写错误必须报错，而不是被静默忽略成「无记录的空区域」。
func TestLoadFileRejectsUnknownFields(t *testing.T) {
	// 顶层未知字段。
	if _, err := LoadFile(writeTemp(t, `{"zones":[{"name":"a.test"}],"exrtra":1}`), 0); err == nil {
		t.Error("顶层未知字段应报错")
	}
	// 嵌套（区域）未知字段。
	if _, err := LoadFile(writeTemp(t, `{"zones":[{"name":"a.test","record":[]}]}`), 0); err == nil {
		t.Error("区域层未知字段应报错（record 应为 records）")
	}
	// 嵌套（记录）未知字段。
	if _, err := LoadFile(writeTemp(t, `{"zones":[{"name":"a.test","records":[{"nam":"www"}]}]}`), 0); err == nil {
		t.Error("记录层未知字段应报错（nam 应为 name）")
	}
}

func TestLoadFileRejectsMalformedJSON(t *testing.T) {
	for name, content := range map[string]string{
		"语法错误":   `{"zones":[{"name":"a.test"}`,
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
