// Package config 提供 telemetryd 运行时配置加载。
//
// 配置优先级（高 -> 低）：命令行 flag > 环境变量 > YAML 文件 > 内置默认值。
// 取值与容错解析复用 cythsec/services/pkg/configutil，不引入第三方 YAML 库。
package config

import (
	"time"

	"cythsec/services/pkg/configutil"
)

// envPrefix 是本服务环境变量前缀，完整键名形如 TELEMETRYD_LISTEN_ADDR。
const envPrefix = "TELEMETRYD"

// Config 是 telemetryd 的运行时配置。
type Config struct {
	ListenAddr      string        // HTTP 监听地址
	ShutdownTimeout time.Duration // 优雅关闭超时
	LogLevel        string        // 日志级别：debug/info/warn/error
	LogFormat       string        // 日志格式：json/text
	MetricsEnabled  bool          // 是否暴露 GET /metrics
	TargetFile      string        // 抓取目标文件路径（空表示不载入，从空注册表启动）
	MaxTargets      int           // 允许载入的最大目标数（0 表示不限制）
	AggregateDir    string        // 聚合持久化目录；空表示未启用，仅本机服务可用
	ConfigPath      string        // YAML 配置文件路径
}

// Default 返回内置默认值。
//
// 监听端口按服务序位分配：routerd 8080 / policyd 8081 / dnsd 8082 /
// telemetryd 8083，便于本机同时启动四个服务联调。
func Default() Config {
	return Config{
		ListenAddr:      ":8083",
		ShutdownTimeout: 10 * time.Second,
		LogLevel:        "info",
		LogFormat:       "json",
		MetricsEnabled:  true,
		MaxTargets:      0,
		ConfigPath:      "configs/config.yaml",
	}
}

// LoadYAML 从配置 YAML 读取并覆盖对应字段。
//
// 文件不存在时直接返回 nil（不打断启动）；键缺失或值非法时该字段保持原值。
func (c *Config) LoadYAML(path string) error {
	m, err := configutil.LoadYAML(path)
	if err != nil {
		return err
	}
	c.ListenAddr = m.Get("listen_addr", c.ListenAddr)
	c.ShutdownTimeout = m.Duration("shutdown_timeout", c.ShutdownTimeout)
	c.LogLevel = m.Get("log_level", c.LogLevel)
	c.LogFormat = m.Get("log_format", c.LogFormat)
	c.MetricsEnabled = m.Bool("metrics_enabled", c.MetricsEnabled)
	c.TargetFile = m.Get("target_file", c.TargetFile)
	c.MaxTargets = m.Int("max_targets", c.MaxTargets)
	c.AggregateDir = m.Get("aggregate_dir", c.AggregateDir)
	return nil
}

// ApplyEnv 用环境变量（TELEMETRYD_* 前缀）覆盖配置。
func (c *Config) ApplyEnv() {
	c.ListenAddr = configutil.EnvString(envPrefix, "listen_addr", c.ListenAddr)
	c.ShutdownTimeout = configutil.EnvDuration(envPrefix, "shutdown_timeout", c.ShutdownTimeout)
	c.LogLevel = configutil.EnvString(envPrefix, "log_level", c.LogLevel)
	c.LogFormat = configutil.EnvString(envPrefix, "log_format", c.LogFormat)
	c.MetricsEnabled = configutil.EnvBool(envPrefix, "metrics_enabled", c.MetricsEnabled)
	c.TargetFile = configutil.EnvString(envPrefix, "target_file", c.TargetFile)
	c.MaxTargets = configutil.EnvInt(envPrefix, "max_targets", c.MaxTargets)
	c.AggregateDir = configutil.EnvString(envPrefix, "aggregate_dir", c.AggregateDir)
	if v, ok := configutil.FromEnv(envPrefix, "config"); ok {
		c.ConfigPath = v
	}
}
