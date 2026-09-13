package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile 写出临时文件并返回路径。
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	return p
}

func TestLoadFileOK(t *testing.T) {
	p := writeFile(t, "p.json", `{
	  "rules": [
	    {"id":"r1","name":"默认放行","priority":10,"enabled":true,"expression":"src in 10.0.0.0/8"},
	    {"id":"r2","name":"阻断扫描","priority":5,"enabled":false}
	  ]
	}`)

	rules, err := LoadFile(p, 0)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("规则数 = %d，期望 2", len(rules))
	}
	if rules[0].ID != "r1" || rules[0].Priority != 10 || !rules[0].Enabled {
		t.Errorf("第 1 条解析错误: %+v", rules[0])
	}
	if rules[1].ID != "r2" || rules[1].Enabled {
		t.Errorf("第 2 条解析错误: %+v", rules[1])
	}
	if rules[1].Expression != "" {
		t.Errorf("未提供的 expression 应为空，实际 %q", rules[1].Expression)
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "absent.json"), 0); err == nil {
		t.Error("文件不存在应返回错误")
	}
}

func TestLoadFileRejectsUnknownField(t *testing.T) {
	// 字段名写错必须报错，而不是被静默忽略 —— 否则「规则没生效」会极难排查。
	p := writeFile(t, "p.json", `{"rules":[{"id":"r1","prioirty":10}]}`)
	_, err := LoadFile(p, 0)
	if err == nil {
		t.Fatal("未知字段应导致解析失败")
	}
	if !strings.Contains(err.Error(), "prioirty") {
		t.Errorf("错误信息应指明问题字段，实际: %v", err)
	}
}

func TestLoadFileRejectsMalformedJSON(t *testing.T) {
	p := writeFile(t, "p.json", `{"rules":[{"id":"r1",}]}`)
	if _, err := LoadFile(p, 0); err == nil {
		t.Error("畸形 JSON 应报错")
	}
}

func TestLoadFileMaxRules(t *testing.T) {
	p := writeFile(t, "p.json", `{"rules":[{"id":"r1"},{"id":"r2"},{"id":"r3"}]}`)

	// maxRules=0 表示不限制。
	if rules, err := LoadFile(p, 0); err != nil || len(rules) != 3 {
		t.Fatalf("maxRules=0 应放行 3 条，实际 %d 条，err=%v", len(rules), err)
	}
	// 恰好等于上限应放行。
	if _, err := LoadFile(p, 3); err != nil {
		t.Errorf("等于上限不应报错，实际 %v", err)
	}
	// 超过上限应报错，且错误信息含实际条数与上限。
	_, err := LoadFile(p, 2)
	if err == nil {
		t.Fatal("超过 maxRules 应报错")
	}
	if !strings.Contains(err.Error(), "3") || !strings.Contains(err.Error(), "max_rules=2") {
		t.Errorf("错误信息应含实际条数与上限，实际: %v", err)
	}
}

func TestLoadFileEmptyRules(t *testing.T) {
	p := writeFile(t, "p.json", `{"rules":[]}`)
	rules, err := LoadFile(p, 0)
	if err != nil {
		t.Fatalf("空规则列表不应报错: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("期望 0 条，实际 %d", len(rules))
	}
}
