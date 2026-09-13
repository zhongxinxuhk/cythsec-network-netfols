// routerd - cythsec 路由器核心服务（控制面）。
//
// 提供本机网络信息采集的只读 HTTP API，作为 Web Console 的数据后端：
//
//	GET /healthz            健康检查
//	GET /metrics            Prometheus 指标（文本格式 0.0.4）
//	GET /api/v1/version     版本 / commit / 构建时间 / Go 版本
//	GET /api/v1/system      系统概貌（hostname / os / arch / go 版本）
//	GET /api/v1/interfaces  网卡、IP、接口状态
//	GET /api/v1/routes      路由表
//	GET /api/v1/traffic     网卡流量计数（rx/tx bytes & packets）
//
// 前两个基础端点与中间件栈由 cythsec/services/pkg/controlplane 统一提供；
// 本文件只负责 flag / 环境变量 / YAML 的配置优先级解析。
//
// 配置优先级：flag > 环境变量 > YAML 文件 > 内置默认值。
package main

import (
	"flag"
	"log"
	"os"

	"cythsec/services/pkg/configutil"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/api"
	"cythsec/services/routerd/internal/config"
)

// loadConfig 按 flag > 环境变量 > YAML > 默认值 的优先级组装配置。
//
// 返回 exited=true 表示已处理完 -version 等「打印即退出」的 flag。
func loadConfig() (config.Config, bool) {
	c := config.Default()

	addr := flag.String("addr", c.ListenAddr, "HTTP 监听地址，如 :8080 或 127.0.0.1:8080")
	cors := flag.String("cors-origins", "", "逗号分隔的允许跨域源，默认 http://localhost:5173")
	shutdown := flag.Duration("shutdown-timeout", c.ShutdownTimeout, "优雅关闭超时（如 10s / 5s）")
	logLevel := flag.String("log-level", "", "日志级别: debug / info / warn / error（默认 info）")
	logFormat := flag.String("log-format", "", "日志格式: json / text（默认 json）")
	noMetrics := flag.Bool("no-metrics", false, "关闭 GET /metrics 端点")
	configPath := flag.String("config", c.ConfigPath, "YAML 配置文件路径")
	showVer := flag.Bool("version", false, "打印版本并退出")
	flag.Parse()

	if *showVer {
		controlplane.PrintVersion(api.ServiceName)
		return c, true
	}

	// 记录用户显式设置的 flag 名。
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// 确定配置文件路径：flag > 环境变量 > 默认值。
	cfgPath := c.ConfigPath
	switch {
	case set["config"]:
		cfgPath = *configPath
	default:
		if v, ok := configutil.FromEnv("ROUTERD", "config"); ok {
			cfgPath = v
		}
	}
	c.ConfigPath = cfgPath

	// YAML 覆盖默认值，环境变量覆盖 YAML。
	if err := c.LoadYAML(c.ConfigPath); err != nil {
		log.Printf("读取配置文件 %s 失败: %v", c.ConfigPath, err)
	}
	c.ApplyEnv()

	// 显式 flag 覆盖环境变量。
	if set["addr"] {
		c.ListenAddr = *addr
	}
	if set["cors-origins"] {
		if origins := configutil.SplitList(*cors); len(origins) > 0 {
			c.CORSAllowedOrigins = origins
		}
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

	return c, false
}

func main() {
	c, exited := loadConfig()
	if exited {
		return
	}

	err := controlplane.Run(controlplane.ServerConfig{
		Service:            api.ServiceName,
		Addr:               c.ListenAddr,
		ShutdownTimeout:    c.ShutdownTimeout,
		LogLevel:           c.LogLevel,
		LogFormat:          c.LogFormat,
		MetricsEnabled:     c.MetricsEnabled,
		CORSAllowedOrigins: c.CORSAllowedOrigins,
	}, api.RegisterRoutes)
	if err != nil {
		log.Printf("routerd 退出: %v", err)
		os.Exit(1)
	}
}
