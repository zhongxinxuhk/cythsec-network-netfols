package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()

	// 端口按服务序位分配，dnsd 占 8082。此断言固化该约定：
	// 若有人误改端口，本测试会失败并提醒同步更新部署文档与联调脚本。
	if c.ListenAddr != ":8082" {
		t.Errorf("ListenAddr = %q，期望 :8082", c.ListenAddr)
	}
	if c.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v，期望 10s", c.ShutdownTimeout)
	}
	if c.LogLevel != "info" || c.LogFormat != "json" {
		t.Errorf("日志默认值异常: level=%q format=%q", c.LogLevel, c.LogFormat)
	}
	if !c.MetricsEnabled {
		t.Error("默认应暴露 /metrics")
	}
	if c.ZoneFile != "" {
		t.Errorf("默认不应载入区域文件，实际 %q", c.ZoneFile)
	}
	if c.ConfigPath != "configs/config.yaml" {
		t.Errorf("ConfigPath = %q", c.ConfigPath)
	}
}

func TestLoadYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	content := `
# 注释应被忽略
listen_addr: "127.0.0.1:9082"
shutdown_timeout: "3s"
log_level: "debug"
log_format: "text"
metrics_enabled: false
zone_file: "/tmp/zones.json"
max_zones: 42
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}

	if c.ListenAddr != "127.0.0.1:9082" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
	if c.ShutdownTimeout != 3*time.Second {
		t.Errorf("ShutdownTimeout = %v，期望 3s", c.ShutdownTimeout)
	}
	if c.LogLevel != "debug" || c.LogFormat != "text" {
		t.Errorf("日志配置未生效: level=%q format=%q", c.LogLevel, c.LogFormat)
	}
	if c.MetricsEnabled {
		t.Error("metrics_enabled: false 未生效")
	}
	if c.ZoneFile != "/tmp/zones.json" {
		t.Errorf("ZoneFile = %q", c.ZoneFile)
	}
	if c.MaxZones != 42 {
		t.Errorf("MaxZones = %d，期望 42", c.MaxZones)
	}
}

func TestLoadYAMLMissingFileIsNotFatal(t *testing.T) {
	// 刻意固化：配置文件缺失不应打断启动，字段保持内置默认值。
	c := Default()
	if err := c.LoadYAML(filepath.Join(t.TempDir(), "absent.yaml")); err != nil {
		t.Fatalf("文件缺失不应报错: %v", err)
	}
	if c.ListenAddr != ":8082" {
		t.Errorf("默认值被改动: %q", c.ListenAddr)
	}
}

// TestLoadYAMLInvalidValuesKeepPrevious 校验容错解析的语义：
// 非法值（如时长写错）应保持原值，而不是被置零或导致启动失败。
func TestLoadYAMLInvalidValuesKeepPrevious(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	content := `
shutdown_timeout: "不是时长"
max_zones: "不是数字"
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("非法值不应导致 LoadYAML 报错: %v", err)
	}
	if c.ShutdownTimeout != 10*time.Second {
		t.Errorf("非法时长应保持默认 10s，实际 %v", c.ShutdownTimeout)
	}
	if c.MaxZones != 0 {
		t.Errorf("非法数字应保持默认 0，实际 %d", c.MaxZones)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	c := Default()
	t.Setenv("DNSD_LISTEN_ADDR", ":7070")
	t.Setenv("DNSD_SHUTDOWN_TIMEOUT", "2s")
	t.Setenv("DNSD_LOG_LEVEL", "warn")
	t.Setenv("DNSD_METRICS_ENABLED", "false")
	t.Setenv("DNSD_ZONE_FILE", "/etc/cythsec/zones.json")
	t.Setenv("DNSD_MAX_ZONES", "7")
	t.Setenv("DNSD_CONFIG", "/etc/cythsec/dnsd.yaml")

	c.ApplyEnv()

	if c.ListenAddr != ":7070" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
	if c.ShutdownTimeout != 2*time.Second {
		t.Errorf("ShutdownTimeout = %v", c.ShutdownTimeout)
	}
	if c.LogLevel != "warn" {
		t.Errorf("LogLevel = %q", c.LogLevel)
	}
	if c.MetricsEnabled {
		t.Error("DNSD_METRICS_ENABLED=false 未生效")
	}
	if c.ZoneFile != "/etc/cythsec/zones.json" {
		t.Errorf("ZoneFile = %q", c.ZoneFile)
	}
	if c.MaxZones != 7 {
		t.Errorf("MaxZones = %d", c.MaxZones)
	}
	if c.ConfigPath != "/etc/cythsec/dnsd.yaml" {
		t.Errorf("ConfigPath = %q", c.ConfigPath)
	}
}

// TestEnvPrefixIsolation 校验环境变量前缀隔离：
// POLICYD_* 这类他服务变量不得影响 dnsd 配置。
func TestEnvPrefixIsolation(t *testing.T) {
	c := Default()
	t.Setenv("POLICYD_LISTEN_ADDR", ":9999")
	c.ApplyEnv()
	if c.ListenAddr != ":8082" {
		t.Errorf("他服务环境变量污染了 dnsd 配置: %q", c.ListenAddr)
	}
}
