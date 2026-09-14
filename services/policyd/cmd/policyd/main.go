// policyd - cythsec 策略服务（控制面）。
//
// 暴露的端点：
//
//	GET /healthz                健康检查
//	GET /metrics                Prometheus 指标（文本格式 0.0.4）
//	GET /api/v1/version         版本 / commit / 构建时间 / Go 版本
//	GET /api/v1/policies        列出全部策略规则
//	GET /api/v1/policies/{id}   查询单条策略规则
//	GET /api/v1/attributes      属性字典与规则编写元数据
//	GET /api/v1/rule-tables     规则表摘要（含版本与诊断计数）
//	POST /api/v1/rule-tables/{name}/evaluate  规则试算（dry-run）
//
// 基础端点与中间件栈由 cythsec/services/pkg/controlplane 统一提供；
// 本文件只负责配置优先级解析与策略载入。
//
// 配置优先级：flag > 环境变量 > YAML 文件 > 内置默认值。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"cythsec/services/pkg/configutil"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/policyd/internal/api"
	"cythsec/services/policyd/internal/config"
	"cythsec/services/policyd/internal/policy"
	"cythsec/services/policyd/internal/ruleir"
)

// loadConfig 按 flag > 环境变量 > YAML > 默认值 的优先级组装配置。
//
// 返回 exited=true 表示已处理完 -version 等「打印即退出」的 flag。
func loadConfig() (config.Config, bool) {
	c := config.Default()

	addr := flag.String("addr", c.ListenAddr, "HTTP 监听地址，如 :8081 或 127.0.0.1:8081")
	shutdown := flag.Duration("shutdown-timeout", c.ShutdownTimeout, "优雅关闭超时（如 10s / 5s）")
	logLevel := flag.String("log-level", "", "日志级别: debug / info / warn / error（默认 info）")
	logFormat := flag.String("log-format", "", "日志格式: json / text（默认 json）")
	noMetrics := flag.Bool("no-metrics", false, "关闭 GET /metrics 端点")
	policyFile := flag.String("policy-file", c.PolicyFile, "JSON 策略文件路径（默认不载入）")
	maxRules := flag.Int("max-rules", c.MaxRules, "允许载入的最大规则数（0 表示不限制）")
	ruleTablesFile := flag.String("rule-tables-file", c.RuleTablesFile, "规则表文件路径（默认不载入）")
	maxRuleTables := flag.Int("max-rule-tables", c.MaxRuleTables, "允许载入的最大规则表数（0 表示不限制）")
	deployMode := flag.String("deploy-mode", c.DeployMode,
		"部署模式: bypass / on_path_inline / on_path_transparent / pcap")
	configPath := flag.String("config", c.ConfigPath, "YAML 配置文件路径")
	showVer := flag.Bool("version", false, "打印版本并退出")
	flag.Parse()

	if *showVer {
		controlplane.PrintVersion(api.ServiceName)
		return c, true
	}

	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfgPath := c.ConfigPath
	switch {
	case set["config"]:
		cfgPath = *configPath
	default:
		if v, ok := configutil.FromEnv("POLICYD", "config"); ok {
			cfgPath = v
		}
	}
	c.ConfigPath = cfgPath

	if err := c.LoadYAML(c.ConfigPath); err != nil {
		log.Printf("读取配置文件 %s 失败: %v", c.ConfigPath, err)
	}
	c.ApplyEnv()

	if set["addr"] {
		c.ListenAddr = *addr
	}
	if set["shutdown-timeout"] {
		c.ShutdownTimeout = *shutdown
	}
	if set["log-level"] {
		c.LogLevel = *logLevel
	}
	if set["log-format"] {
		c.LogFormat = *logFormat
	}
	if set["no-metrics"] {
		c.MetricsEnabled = !*noMetrics
	}
	if set["policy-file"] {
		c.PolicyFile = *policyFile
	}
	if set["max-rules"] {
		c.MaxRules = *maxRules
	}
	if set["rule-tables-file"] {
		c.RuleTablesFile = *ruleTablesFile
	}
	if set["max-rule-tables"] {
		c.MaxRuleTables = *maxRuleTables
	}
	if set["deploy-mode"] {
		c.DeployMode = *deployMode
	}

	return c, false
}

// loadRuleTables 按配置装载规则表并返回版本化持有器。
//
// 失败即致命：规则表是安全策略，静默以空表启动等于把全部阻断规则失效，而这种
// 「看起来正常」的降级最难被发现。同理，编译期诊断的 error 级问题由 ruleir 拒绝装载，
// 这里不做任何「跳过问题规则」的宽容处理。
func loadRuleTables(c config.Config) (*ruleir.Registry, ruleir.DeployMode, error) {
	mode := ruleir.DeployMode(c.DeployMode)
	if !mode.Valid() {
		return nil, mode, fmt.Errorf("部署模式 %q 未登记（可用：bypass / on_path_inline / "+
			"on_path_transparent / pcap）", c.DeployMode)
	}

	reg := ruleir.NewRegistry()
	if c.RuleTablesFile == "" {
		return reg, mode, nil
	}

	snap, err := ruleir.LoadAndInstall(context.Background(),
		ruleir.NewFileStore(c.RuleTablesFile, c.MaxRuleTables), reg,
		ruleir.CompileOptions{Mode: mode})
	if err != nil {
		return nil, mode, err
	}
	log.Printf("已装载规则表: 文件=%s 表数=%d revision=%d 校验和=%s 部署模式=%s",
		c.RuleTablesFile, len(snap.Tables), snap.Version.Revision,
		snap.Version.Checksum[:12], mode)
	for _, d := range snap.Diagnostics {
		// 提示级诊断直接打印：它们正是「规则可能不按预期生效」的先行指标。
		log.Printf("规则诊断 %s", d.String())
	}
	return reg, mode, nil
}

// loadPolicies 按配置载入策略文件（未配置时返回空切片，即从空策略启动）。
func loadPolicies(c config.Config) ([]policy.Rule, error) {
	if c.PolicyFile == "" {
		return nil, nil
	}
	return policy.LoadFile(c.PolicyFile, c.MaxRules)
}

func main() {
	c, exited := loadConfig()
	if exited {
		return
	}

	rules, err := loadPolicies(c)
	if err != nil {
		// 策略载入失败属致命错误：静默以空策略启动会让本该生效的访问控制失效，
		// 这种「看起来正常」的降级比直接退出更危险。
		log.Printf("载入策略失败，进程退出: %v", err)
		os.Exit(1)
	}

	store := policy.NewStore()
	if err := store.Load(rules); err != nil {
		log.Printf("载入策略失败，进程退出: %v", err)
		os.Exit(1)
	}

	ruleRegistry, deployMode, err := loadRuleTables(c)
	if err != nil {
		log.Printf("载入规则表失败，进程退出: %v", err)
		os.Exit(1)
	}

	var ruleCount *metrics.Gauge
	err = controlplane.Run(controlplane.ServerConfig{
		Service:            api.ServiceName,
		Addr:               c.ListenAddr,
		ShutdownTimeout:    c.ShutdownTimeout,
		LogLevel:           c.LogLevel,
		LogFormat:          c.LogFormat,
		MetricsEnabled:     c.MetricsEnabled,
		CORSAllowedOrigins: nil, // 使用 controlplane 默认值
		RegisterMetrics: func(reg *metrics.Registry) error {
			ruleCount = api.NewRuleCountGauge(reg)
			return nil
		},
	}, func(mux *http.ServeMux) {
		api.RegisterRoutes(mux, api.ServerOptions{
			Store:        store,
			RuleCount:    ruleCount,
			RuleRegistry: ruleRegistry,
			DeployMode:   deployMode,
		})
	})
	if err != nil {
		log.Printf("policyd 退出: %v", err)
		os.Exit(1)
	}
}
