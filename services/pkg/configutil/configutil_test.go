package configutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseYAMLBasic(t *testing.T) {
	raw := []byte(`
# 全行注释应被忽略
listen_addr: ":8080"
log_level: debug
log_format: "json"
shutdown_timeout: 10s

metrics_enabled: true
cors_origins: "http://a, http://b"
unquoted_hash: value # 行内注释不支持，会整体保留
no_colon_line
`)
	m := ParseYAML(raw)

	cases := map[string]string{
		"listen_addr":      ":8080",
		"log_level":        "debug",
		"log_format":       "json",
		"shutdown_timeout": "10s",
		"metrics_enabled":  "true",
		"cors_origins":     "http://a, http://b",
		"unquoted_hash":    "value # 行内注释不支持，会整体保留",
	}
	for k, want := range cases {
		if got := m[k]; got != want {
			t.Errorf("键 %q 期望 %q，实际 %q", k, want, got)
		}
	}
	// 无冒号的行应被忽略，且不应产生空键。
	if _, ok := m["no_colon_line"]; ok {
		t.Error("无冒号行不应被解析为键值")
	}
	if v, ok := m[""]; ok {
		t.Errorf("不应存在空键，实际值为 %q", v)
	}
}

func TestMapGet(t *testing.T) {
	m := Map{"a": "1", "empty": ""}

	if got := m.Get("a", "def"); got != "1" {
		t.Errorf("已存在键期望 \"1\"，实际 %q", got)
	}
	// 空值视为未设置，回落到默认值。
	if got := m.Get("empty", "def"); got != "def" {
		t.Errorf("空值应回落默认值，实际 %q", got)
	}
	if got := m.Get("missing", "def"); got != "def" {
		t.Errorf("缺失键应返回默认值，实际 %q", got)
	}
}

func TestMapTypedAccessors(t *testing.T) {
	m := Map{
		"dur":        "3s",
		"dur_bad":    "abc",
		"flag":       "false",
		"bool_liar":  "yes-please",
		"num":        "42",
		"num_bad":    "4x2",
		"list":       "a, b ,,c",
		"list_empty": "  ",
	}

	if got := m.Duration("dur", time.Second); got != 3*time.Second {
		t.Errorf("Duration 期望 3s，实际 %v", got)
	}
	if got := m.Duration("dur_bad", 7*time.Second); got != 7*time.Second {
		t.Errorf("非法时长应回落默认值，实际 %v", got)
	}
	if got := m.Duration("nope", 9*time.Second); got != 9*time.Second {
		t.Errorf("缺失键应回落默认值，实际 %v", got)
	}

	if got := m.Bool("flag", true); got != false {
		t.Errorf("Bool 期望 false，实际 %v", got)
	}
	if got := m.Bool("bool_liar", true); got != true {
		t.Errorf("非法布尔应回落默认值，实际 %v", got)
	}

	if got := m.Int("num", 0); got != 42 {
		t.Errorf("Int 期望 42，实际 %d", got)
	}
	if got := m.Int("num_bad", 5); got != 5 {
		t.Errorf("非法整数应回落默认值，实际 %d", got)
	}

	got := m.List("list", nil)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("List 期望 %v，实际 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List 期望 %v，实际 %v", want, got)
		}
	}

	def := []string{"x"}
	// 全空白值视为未设置。
	if got := m.List("list_empty", def); len(got) != 1 || got[0] != "x" {
		t.Errorf("空白列表应回落默认值，实际 %v", got)
	}
	if got := m.List("nope", def); len(got) != 1 || got[0] != "x" {
		t.Errorf("缺失列表应回落默认值，实际 %v", got)
	}
}

func TestLoadYAMLMissingFileIsNotError(t *testing.T) {
	m, err := LoadYAML(filepath.Join(t.TempDir(), "not-there.yaml"))
	if err != nil {
		t.Fatalf("文件缺失不应返回错误，实际 %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("文件缺失应返回空 Map，实际 %v", m)
	}
}

func TestLoadYAMLRealFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("listen_addr: 127.0.0.1:9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadYAML(p)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got := m.Get("listen_addr", ""); got != "127.0.0.1:9999" {
		t.Errorf("期望 127.0.0.1:9999，实际 %q", got)
	}
}

func TestSplitList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a,b", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{"a,,b,", []string{"a", "b"}},
		{"", []string{}},
		{"  ", []string{}},
		{"solo", []string{"solo"}},
	}
	for _, c := range cases {
		got := SplitList(c.in)
		if len(got) != len(c.want) {
			t.Errorf("SplitList(%q) 期望 %v，实际 %v", c.in, c.want, got)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("SplitList(%q) 期望 %v，实际 %v", c.in, c.want, got)
				break
			}
		}
	}
}

func TestFromEnvAndHelpers(t *testing.T) {
	const prefix = "CYTHSEC_TESTCFG"
	t.Setenv(prefix+"_LISTEN_ADDR", "127.0.0.1:1234")
	t.Setenv(prefix+"_METRICS_ENABLED", "false")
	t.Setenv(prefix+"_SHUTDOWN_TIMEOUT", "2s")
	t.Setenv(prefix+"_CORS_ORIGINS", "http://a,http://b")
	// 空串视为未设置。
	t.Setenv(prefix+"_EMPTY", "")

	// 键名大小写不敏感（内部统一转大写）。
	if v, ok := FromEnv(prefix, "listen_addr"); !ok || v != "127.0.0.1:1234" {
		t.Errorf("FromEnv 期望命中，实际 (%q, %v)", v, ok)
	}
	if _, ok := FromEnv(prefix, "empty"); ok {
		t.Error("空值不应视为命中")
	}
	if _, ok := FromEnv(prefix, "missing"); ok {
		t.Error("缺失键不应视为命中")
	}

	if got := EnvString(prefix, "missing", "def"); got != "def" {
		t.Errorf("EnvString 期望 def，实际 %q", got)
	}
	if got := EnvBool(prefix, "metrics_enabled", true); got != false {
		t.Errorf("EnvBool 期望 false，实际 %v", got)
	}
	if got := EnvBool(prefix, "missing", true); got != true {
		t.Errorf("EnvBool 缺失时应回落默认值，实际 %v", got)
	}
	if got := EnvDuration(prefix, "shutdown_timeout", time.Minute); got != 2*time.Second {
		t.Errorf("EnvDuration 期望 2s，实际 %v", got)
	}
	if got := EnvDuration(prefix, "missing", time.Minute); got != time.Minute {
		t.Errorf("EnvDuration 缺失时应回落默认值，实际 %v", got)
	}
	got := EnvList(prefix, "cors_origins", nil)
	if len(got) != 2 || got[0] != "http://a" || got[1] != "http://b" {
		t.Errorf("EnvList 结果不符: %v", got)
	}
	if got := EnvList(prefix, "missing", []string{"z"}); len(got) != 1 || got[0] != "z" {
		t.Errorf("EnvList 缺失时应回落默认值，实际 %v", got)
	}
}
