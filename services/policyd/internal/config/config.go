// Package config 提供 policyd 运行时配置加载。
//
// 配置优先级（高 -> 低）：命令行 flag > 环境变量 > YAML 文件 > 内置默认值。
// 取值与容错解析复用 cythsec/services/pkg/configutil，不引入第三方 YAML 库。
package config

import (
	"time"

	"cythsec/services/pkg/configutil"
)

// envPrefix 是本服务环境变量前缀，完整键名形如 POLICYD_LISTEN_ADDR。
const envPrefix = "POLICYD"

// Config 是 policyd 的运行时配置。
type Config struct {
	ListenAddr      string        // HTTP 监听地址
	ShutdownTimeout time.Duration // 优雅关闭超时
	LogLevel        string        // 日志级别：debug/info/warn/error
	LogFormat       string        // 日志格式：json/text
	MetricsEnabled  bool          // 是否暴露 GET /metrics
	PolicyFile      string        // 策略文件路径（空表示不载入，从空存储启动）
	MaxRules        int           // 允许载入的最大规则数（0 表示不限制）
	// RuleTablesFile 是规则表文件路径（ruleir JSON 格式）；空表示不装载。
	RuleTablesFile string
	// MaxRuleTables 是允许载入的最大规则表数（0 表示不限制）。
	MaxRuleTables int
	// DeployMode 是部署模式，决定哪些处置原语可用。
	// 默认 bypass（旁路）：旁路部署物理上无法丢包/限速，因此这是唯一「不会误以为
	// 已生效」的默认值 —— 若默认成在线，配置成旁路时会静默地什么都没发生。
	DeployMode string
	ConfigPath string // YAML 配置文件路径
}

// Default 返回内置默认值。
//
// 监听端口按服务序位分配：routerd 8080 / policyd 8081 / dnsd 8082 /
// telemetryd 8083，便于本机同时启动四个服务联调。
func Default() Config {
	return Config{
		ListenAddr:      ":8081",
		ShutdownTimeout: 10 * time.Second,
		LogLevel:        "info",
		LogFormat:       "json",
		MetricsEnabled:  true,
		MaxRules:        0,
		MaxRuleTables:   0,
		DeployMode:      "bypass",
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
	c.PolicyFile = m.Get("policy_file", c.PolicyFile)
	c.MaxRules = m.Int("max_rules", c.MaxRules)
	c.RuleTablesFile = m.Get("rule_tables_file", c.RuleTablesFile)
	c.MaxRuleTables = m.Int("max_rule_tables", c.MaxRuleTables)
	c.DeployMode = m.Get("deploy_mode", c.DeployMode)
	return nil
}

// ApplyEnv 用环境变量（POLICYD_* 前缀）覆盖配置。
func (c *Config) ApplyEnv() {
	c.ListenAddr = configutil.EnvString(envPrefix, "listen_addr", c.ListenAddr)
	c.ShutdownTimeout = configutil.EnvDuration(envPrefix, "shutdown_timeout", c.ShutdownTimeout)
	c.LogLevel = configutil.EnvString(envPrefix, "log_level", c.LogLevel)
	c.LogFormat = configutil.EnvString(envPrefix, "log_format", c.LogFormat)
	c.MetricsEnabled = configutil.EnvBool(envPrefix, "metrics_enabled", c.MetricsEnabled)
	c.PolicyFile = configutil.EnvString(envPrefix, "policy_file", c.PolicyFile)
	c.MaxRules = configutil.EnvInt(envPrefix, "max_rules", c.MaxRules)
	c.RuleTablesFile = configutil.EnvString(envPrefix, "rule_tables_file", c.RuleTablesFile)
	c.MaxRuleTables = configutil.EnvInt(envPrefix, "max_rule_tables", c.MaxRuleTables)
	c.DeployMode = configutil.EnvString(envPrefix, "deploy_mode", c.DeployMode)
	if v, ok := configutil.FromEnv(envPrefix, "config"); ok {
		c.ConfigPath = v
	}
}
