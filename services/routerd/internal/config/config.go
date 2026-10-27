// Package config 提供 routerd 运行时配置加载。
//
// 配置优先级（高 -> 低）：命令行 flag > 环境变量 > YAML 文件 > 内置默认值。
// 后三层的取值与容错解析复用 cythsec/services/pkg/configutil，避免各服务各自
// 维护同一套极简 YAML 解析逻辑（该子集不引入第三方依赖，离线可构建）。
package config

import (
	"time"

	"cythsec/services/pkg/configutil"
)

// envPrefix 是本服务环境变量前缀，完整键名形如 ROUTERD_LISTEN_ADDR。
const envPrefix = "ROUTERD"

// Config 是 routerd 的运行时配置。
type Config struct {
	NetworkConfigDir   string
	AccessFile         string
	ListenAddr         string        // HTTP 监听地址
	ShutdownTimeout    time.Duration // 优雅关闭超时
	CORSAllowedOrigins []string      // 允许跨域的源列表
	LogLevel           string        // 日志级别：debug/info/warn/error
	LogFormat          string        // 日志格式：json/text
	MetricsEnabled     bool          // 是否暴露 GET /metrics
	ConfigPath         string        // YAML 配置文件路径
}

// Default 返回内置默认值。
func Default() Config {
	return Config{
		ListenAddr:         "127.0.0.1:8080",
		ShutdownTimeout:    10 * time.Second,
		CORSAllowedOrigins: []string{"http://localhost:5173"},
		LogLevel:           "info",
		LogFormat:          "json",
		MetricsEnabled:     true,
		ConfigPath:         "configs/config.yaml",
	}
}

// LoadYAML 从配置 YAML 读取并覆盖对应字段。
//
// 文件不存在时直接返回 nil（不打断启动，沿用既有值）；键缺失、值为空或
// 类型解析失败时该字段保持原值。读取失败返回错误。
func (c *Config) LoadYAML(path string) error {
	m, err := configutil.LoadYAML(path)
	if err != nil {
		return err
	}
	c.NetworkConfigDir = m.Get("network_config_dir", c.NetworkConfigDir)
	c.AccessFile = m.Get("access_file", c.AccessFile)
	c.ListenAddr = m.Get("listen_addr", c.ListenAddr)
	c.CORSAllowedOrigins = m.List("cors_origins", c.CORSAllowedOrigins)
	c.ShutdownTimeout = m.Duration("shutdown_timeout", c.ShutdownTimeout)
	c.LogLevel = m.Get("log_level", c.LogLevel)
	c.LogFormat = m.Get("log_format", c.LogFormat)
	c.MetricsEnabled = m.Bool("metrics_enabled", c.MetricsEnabled)
	return nil
}

// ApplyEnv 用环境变量（ROUTERD_* 前缀）覆盖配置。
func (c *Config) ApplyEnv() {
	c.NetworkConfigDir = configutil.EnvString(envPrefix, "network_config_dir", c.NetworkConfigDir)
	c.AccessFile = configutil.EnvString(envPrefix, "access_file", c.AccessFile)
	c.ListenAddr = configutil.EnvString(envPrefix, "listen_addr", c.ListenAddr)
	c.CORSAllowedOrigins = configutil.EnvList(envPrefix, "cors_origins", c.CORSAllowedOrigins)
	c.ShutdownTimeout = configutil.EnvDuration(envPrefix, "shutdown_timeout", c.ShutdownTimeout)
	c.LogLevel = configutil.EnvString(envPrefix, "log_level", c.LogLevel)
	c.LogFormat = configutil.EnvString(envPrefix, "log_format", c.LogFormat)
	c.MetricsEnabled = configutil.EnvBool(envPrefix, "metrics_enabled", c.MetricsEnabled)
	if v, ok := configutil.FromEnv(envPrefix, "config"); ok {
		c.ConfigPath = v
	}
}
