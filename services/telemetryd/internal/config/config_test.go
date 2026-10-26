package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()

	// 端口按服务序位分配，telemetryd 占 8083。此断言固化该约定：
	// 若有人误改端口，本测试会失败并提醒同步更新部署文档与联调脚本。
	if c.ListenAddr != ":8083" {
		t.Errorf("ListenAddr = %q，期望 :8083", c.ListenAddr)
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
	if c.TargetFile != "" {
		t.Errorf("默认不应载入目标文件，实际 %q", c.TargetFile)
	}
	if c.ConfigPath != "configs/config.yaml" {
		t.Errorf("ConfigPath = %q", c.ConfigPath)
	}
}

func TestLoadYAMLOverrides(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	content := `
# 注释应被忽略
listen_addr: "127.0.0.1:9083"
shutdown_timeout: "3s"
log_level: "debug"
log_format: "text"
metrics_enabled: false
target_file: "/tmp/targets.json"
max_targets: 42
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.LoadYAML(p); err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}

	if c.ListenAddr != "127.0.0.1:9083" {
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
	if c.TargetFile != "/tmp/targets.json" {
		t.Errorf("TargetFile = %q", c.TargetFile)
	}
	if c.MaxTargets != 42 {
		t.Errorf("MaxTargets = %d，期望 42", c.MaxTargets)
	}
}

func TestLoadYAMLMissingFileIsNotFatal(t *testing.T) {
	// 刻意固化：配置文件缺失不应打断启动，字段保持内置默认值。
	c := Default()
	if err := c.LoadYAML(filepath.Join(t.TempDir(), "absent.yaml")); err != nil {
		t.Fatalf("文件缺失不应报错: %v", err)
	}
	if c.ListenAddr != ":8083" {
		t.Errorf("默认值被改动: %q", c.ListenAddr)
	}
}

// TestLoadYAMLInvalidValuesKeepPrevious 校验容错解析的语义：
// 非法值（如时长写错）应保持原值，而不是被置零或导致启动失败。
func TestLoadYAMLInvalidValuesKeepPrevious(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	content := `
shutdown_timeout: "不是时长"
max_targets: "不是数字"
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
	if c.MaxTargets != 0 {
		t.Errorf("非法数字应保持默认 0，实际 %d", c.MaxTargets)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	c := Default()
	t.Setenv("TELEMETRYD_LISTEN_ADDR", ":7070")
	t.Setenv("TELEMETRYD_SHUTDOWN_TIMEOUT", "2s")
	t.Setenv("TELEMETRYD_LOG_LEVEL", "warn")
	t.Setenv("TELEMETRYD_METRICS_ENABLED", "false")
	t.Setenv("TELEMETRYD_TARGET_FILE", "/etc/cythsec/targets.json")
	t.Setenv("TELEMETRYD_MAX_TARGETS", "7")
	t.Setenv("TELEMETRYD_CONFIG", "/etc/cythsec/telemetryd.yaml")

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
		t.Error("TELEMETRYD_METRICS_ENABLED=false 未生效")
	}
	if c.TargetFile != "/etc/cythsec/targets.json" {
		t.Errorf("TargetFile = %q", c.TargetFile)
	}
	if c.MaxTargets != 7 {
		t.Errorf("MaxTargets = %d", c.MaxTargets)
	}
	if c.ConfigPath != "/etc/cythsec/telemetryd.yaml" {
		t.Errorf("ConfigPath = %q", c.ConfigPath)
	}
}

// TestEnvPrefixIsolation 校验环境变量前缀隔离：
// DNSD_* / POLICYD_* 这类他服务变量不得影响 telemetryd 配置。
//
// 这在实际部署中很容易踩到 —— 四个服务常跑在同一台机器上，
// 若前缀匹配写成前缀包含关系（TELEMETRYD 与 DNSD 无包含关系，
// 但未来新增服务名时有可能），就会出现难以定位的串配置。
func TestEnvPrefixIsolation(t *testing.T) {
	c := Default()
	t.Setenv("DNSD_LISTEN_ADDR", ":9999")
	t.Setenv("POLICYD_LISTEN_ADDR", ":9998")
	t.Setenv("ROUTERD_LISTEN_ADDR", ":9997")
	c.ApplyEnv()
	if c.ListenAddr != ":8083" {
		t.Errorf("他服务环境变量污染了 telemetryd 配置: %q", c.ListenAddr)
	}
}

func TestAggregateDirectoryConfiguration(t *testing.T) {
	c := Default()
	if c.AggregateDir != "" {
		t.Fatal("persistence must be explicit")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("aggregate_dir: /local/aggregate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.LoadYAML(p); err != nil {
		t.Fatal(err)
	}
	if c.AggregateDir != "/local/aggregate" {
		t.Fatal(c.AggregateDir)
	}
	t.Setenv("TELEMETRYD_AGGREGATE_DIR", "/env/aggregate")
	c.ApplyEnv()
	if c.AggregateDir != "/env/aggregate" {
		t.Fatal(c.AggregateDir)
	}
}

func TestAggregateQueueConfiguration(t *testing.T) {
	c := Default()
	if c.AggregateQueueDir != "" {
		t.Fatal("queue enabled by default")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("aggregate_queue_dir: /local/queue\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.LoadYAML(p); err != nil {
		t.Fatal(err)
	}
	if c.AggregateQueueDir != "/local/queue" {
		t.Fatal(c.AggregateQueueDir)
	}
	t.Setenv("TELEMETRYD_AGGREGATE_QUEUE_DIR", "/env/queue")
	c.ApplyEnv()
	if c.AggregateQueueDir != "/env/queue" {
		t.Fatal(c.AggregateQueueDir)
	}
}
