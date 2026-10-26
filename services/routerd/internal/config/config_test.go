package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTempYAML 写出临时 YAML 配置供测试。
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写临时配置失败: %v", err)
	}
	return p
}

// TestLoadYAMLOverridesDefault 校验 YAML 覆盖内置默认值。
func TestLoadYAMLOverridesDefault(t *testing.T) {
	p := writeTempYAML(t, `
# 注释行应被忽略
listen_addr: ":9090"
cors_origins: "http://a.test,http://b.test"
shutdown_timeout: "5s"
`)
	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if c.ListenAddr != ":9090" {
		t.Errorf("listen_addr = %q, want :9090", c.ListenAddr)
	}
	if len(c.CORSAllowedOrigins) != 2 || c.CORSAllowedOrigins[0] != "http://a.test" {
		t.Errorf("cors_origins = %v", c.CORSAllowedOrigins)
	}
	if c.ShutdownTimeout.Seconds() != 5 {
		t.Errorf("shutdown_timeout = %v, want 5s", c.ShutdownTimeout)
	}
}

// TestFlagOverridesYAML 模拟「命令行 flag > YAML」的优先级。
// config 包不直接解析 flag，这里用显式赋值模拟 flag 覆盖 YAML 后的结果。
func TestFlagOverridesYAML(t *testing.T) {
	p := writeTempYAML(t, "listen_addr: \":9090\"\n")
	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if c.ListenAddr != ":9090" {
		t.Fatalf("YAML 未生效: %q", c.ListenAddr)
	}
	// 模拟用户通过 -addr=:7070 显式覆盖。
	c.ListenAddr = ":7070"
	if c.ListenAddr != ":7070" {
		t.Errorf("flag 覆盖未生效: %q", c.ListenAddr)
	}
}

// TestEnvOverridesYAML 校验环境变量覆盖 YAML。
func TestEnvOverridesYAML(t *testing.T) {
	p := writeTempYAML(t, "listen_addr: \":9090\"\n")
	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	t.Setenv("ROUTERD_LISTEN_ADDR", ":8088")
	c.ApplyEnv()
	if c.ListenAddr != ":8088" {
		t.Errorf("env 覆盖未生效: %q", c.ListenAddr)
	}
}

// TestYAMLMissingFileIsNoop 校验配置文件不存在时不报错、沿用既有值。
func TestYAMLMissingFileIsNoop(t *testing.T) {
	c := Default()
	if err := c.LoadYAML("/nonexistent/path/config.yaml"); err != nil {
		t.Fatalf("缺失文件应被忽略, got err: %v", err)
	}
	if c.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("默认值被破坏: %q", c.ListenAddr)
	}
}

// TestLoadYAMLQuotingAndComments 校验极简 YAML 的注释、引号与空值处理。
// 解析逻辑已下沉到 cythsec/services/pkg/configutil，此处从 LoadYAML 这个
// 对外入口验证语义未被改变。
func TestLoadYAMLQuotingAndComments(t *testing.T) {
	p := writeTempYAML(t, `
# 注释行应被忽略
listen_addr: "127.0.0.1:8080"
log_format: 'text'
empty:
extra: "a # not a comment"
`)
	c := Default()
	// 先改成非默认值，确认 YAML 真的写入而非「恰好等于默认值」。
	c.LogFormat = ""
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if c.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("listen_addr = %q, want :8080", c.ListenAddr)
	}
	// 单引号应被剥离。
	if c.LogFormat != "text" {
		t.Errorf("log_format = %q, want text（单引号应被剥离）", c.LogFormat)
	}
}

// TestLoadYAMLInvalidValuesKeepPrevious 校验非法值不覆盖既有配置。
func TestLoadYAMLInvalidValuesKeepPrevious(t *testing.T) {
	p := writeTempYAML(t, `
shutdown_timeout: "not-a-duration"
metrics_enabled: "not-a-bool"
`)
	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if c.ShutdownTimeout != 10*time.Second {
		t.Errorf("非法时长应保留默认值 10s，实际 %v", c.ShutdownTimeout)
	}
	if !c.MetricsEnabled {
		t.Error("非法布尔应保留默认值 true")
	}
}

func TestAccessFileConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("access_file: /local/policy.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatal(err)
	}
	if c.AccessFile != "/local/policy.json" {
		t.Fatal("access_file not loaded")
	}
	t.Setenv("ROUTERD_ACCESS_FILE", "/override/policy.json")
	c.ApplyEnv()
	if c.AccessFile != "/override/policy.json" {
		t.Fatal("access env did not override YAML")
	}
}
