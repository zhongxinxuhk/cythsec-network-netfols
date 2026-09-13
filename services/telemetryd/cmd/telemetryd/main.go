// telemetryd - cythsec 遥测服务（控制面）。
//
// 暴露的端点：
//
//	GET /healthz                 健康检查
//	GET /metrics                 Prometheus 指标（文本格式 0.0.4）
//	GET /api/v1/version          版本 / commit / 构建时间 / Go 版本
//	GET /api/v1/targets          列出全部抓取目标
//	GET /api/v1/targets/{name}   按名查询单个抓取目标
//
// 基础端点与中间件栈由 cythsec/services/pkg/controlplane 统一提供；
// 本文件只负责配置优先级解析与抓取目标载入。
//
// 当前范围明确限定为控制面骨架：抓取目标的数据模型、校验规则、内存注册表
// 与只读查询接口。不含实际 HTTP 抓取、调度循环、时序缓存、告警规则 ——
// 这些依次是 CYS-TEL-003 至 CYS-TEL-013 的工作。
//
// 配置优先级：flag > 环境变量 > YAML 文件 > 内置默认值。
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"cythsec/services/pkg/configutil"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/telemetryd/internal/api"
	"cythsec/services/telemetryd/internal/config"
	"cythsec/services/telemetryd/internal/target"
)

// loadConfig 按 flag > 环境变量 > YAML > 默认值 的优先级组装配置。
//
// 返回 exited=true 表示已处理完 -version 等「打印即退出」的 flag。
func loadConfig() (config.Config, bool) {
	c := config.Default()

	addr := flag.String("addr", c.ListenAddr, "HTTP 监听地址，如 :8083 或 127.0.0.1:8083")
	shutdown := flag.Duration("shutdown-timeout", c.ShutdownTimeout, "优雅关闭超时（如 10s / 5s）")
	logLevel := flag.String("log-level", "", "日志级别: debug / info / warn / error（默认 info）")
	logFormat := flag.String("log-format", "", "日志格式: json / text（默认 json）")
	noMetrics := flag.Bool("no-metrics", false, "关闭 GET /metrics 端点")
	targetFile := flag.String("target-file", c.TargetFile, "JSON 抓取目标文件路径（默认不载入）")
	maxTargets := flag.Int("max-targets", c.MaxTargets, "允许载入的最大目标数（0 表示不限制）")
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
		if v, ok := configutil.FromEnv("TELEMETRYD", "config"); ok {
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
	if set["target-file"] {
		c.TargetFile = *targetFile
	}
	if set["max-targets"] {
		c.MaxTargets = *maxTargets
	}

	return c, false
}

// loadTargets 按配置载入目标文件（未配置时返回空切片，即从空注册表启动）。
func loadTargets(c config.Config) ([]target.Target, error) {
	if c.TargetFile == "" {
		return nil, nil
	}
	return target.LoadFile(c.TargetFile, c.MaxTargets)
}

func main() {
	c, exited := loadConfig()
	if exited {
		return
	}

	targets, err := loadTargets(c)
	if err != nil {
		// 目标载入失败属致命错误：静默以空注册表启动会让本该被采集的服务
		// 完全不产生遥测数据，且服务自身健康检查仍然通过 —— 这种「看起来
		// 正常」的降级比直接退出更危险。
		log.Printf("载入抓取目标失败，进程退出: %v", err)
		os.Exit(1)
	}

	store := target.NewStore()
	if err := store.Load(targets); err != nil {
		log.Printf("载入抓取目标失败，进程退出: %v", err)
		os.Exit(1)
	}

	var obs api.ObservabilityMetrics
	err = controlplane.Run(controlplane.ServerConfig{
		Service:            api.ServiceName,
		Addr:               c.ListenAddr,
		ShutdownTimeout:    c.ShutdownTimeout,
		LogLevel:           c.LogLevel,
		LogFormat:          c.LogFormat,
		MetricsEnabled:     c.MetricsEnabled,
		CORSAllowedOrigins: nil, // 使用 controlplane 默认值
		RegisterMetrics: func(reg *metrics.Registry) error {
			obs = api.NewMetrics(reg)
			return nil
		},
	}, func(mux *http.ServeMux) {
		api.RegisterRoutes(mux, api.ServerOptions{
			Store:        store,
			TargetCount:  obs.TargetCount,
			EnabledCount: obs.EnabledCount,
		})
	})
	if err != nil {
		log.Printf("telemetryd 退出: %v", err)
		os.Exit(1)
	}
}
