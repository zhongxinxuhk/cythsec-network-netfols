// dnsd - cythsec DNS 服务（控制面）。
//
// 暴露的端点：
//
//	GET /healthz                健康检查
//	GET /metrics                Prometheus 指标（文本格式 0.0.4）
//	GET /api/v1/version         版本 / commit / 构建时间 / Go 版本
//	GET /api/v1/zones           列出全部区域
//	GET /api/v1/zones/{name}    按区域名查询单个区域
//
// 基础端点与中间件栈由 cythsec/services/pkg/controlplane 统一提供；
// 本文件只负责配置优先级解析与区域载入。
//
// 当前范围明确限定为控制面骨架：区域数据模型、内存存储、查询接口。
// 不含 DNS 报文收发、RFC 1035 master file 解析、递归/转发与缓存 ——
// 这些属于后续里程碑（见 BACKLOG 的 M5 段）。
//
// 配置优先级：flag > 环境变量 > YAML 文件 > 内置默认值。
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"cythsec/services/dnsd/internal/api"
	"cythsec/services/dnsd/internal/config"
	"cythsec/services/dnsd/internal/dns"
	"cythsec/services/pkg/configutil"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
)

// loadConfig 按 flag > 环境变量 > YAML > 默认值 的优先级组装配置。
//
// 返回 exited=true 表示已处理完 -version 等「打印即退出」的 flag。
func loadConfig() (config.Config, bool) {
	c := config.Default()

	addr := flag.String("addr", c.ListenAddr, "HTTP 监听地址，如 :8082 或 127.0.0.1:8082")
	shutdown := flag.Duration("shutdown-timeout", c.ShutdownTimeout, "优雅关闭超时（如 10s / 5s）")
	logLevel := flag.String("log-level", "", "日志级别: debug / info / warn / error（默认 info）")
	logFormat := flag.String("log-format", "", "日志格式: json / text（默认 json）")
	noMetrics := flag.Bool("no-metrics", false, "关闭 GET /metrics 端点")
	zoneFile := flag.String("zone-file", c.ZoneFile, "JSON 区域文件路径（默认不载入）")
	maxZones := flag.Int("max-zones", c.MaxZones, "允许载入的最大区域数（0 表示不限制）")
	configPath := flag.String("config", c.ConfigPath, "YAML 配置文件路径")
	showVer := flag.Bool("version", false, "打印版本并退出")
	flag.Parse()

	if *showVer {
		controlplane.PrintVersion(api.ServiceName)
		return c, true
	}

	// set 记录「用户显式传入」的 flag 名。只有显式传入的 flag 才覆盖配置文件，
	// 未传入的保持其默认值占位、由 YAML/环境变量填充。
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// 配置文件路径本身也遵循优先级：显式 -config > 环境变量；否则沿用默认路径。
	cfgPath := c.ConfigPath
	switch {
	case set["config"]:
		cfgPath = *configPath
	default:
		if v, ok := configutil.FromEnv("DNSD", "config"); ok {
			cfgPath = v
		}
	}
	c.ConfigPath = cfgPath

	// 先载 YAML 再叠环境变量，两者均只覆盖「已有值」；文件缺失/键非法时
	// 该字段保持原值（LoadYAML 已容错），故不会打断启动。
	if err := c.LoadYAML(c.ConfigPath); err != nil {
		log.Printf("读取配置文件 %s 失败: %v", c.ConfigPath, err)
	}
	c.ApplyEnv()

	// 最后才用显式 flag 覆盖，从而落到「flag > 环境变量 > YAML > 默认值」。
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
	if set["zone-file"] {
		c.ZoneFile = *zoneFile
	}
	if set["max-zones"] {
		c.MaxZones = *maxZones
	}

	return c, false
}

// loadZones 按配置载入区域文件（未配置时返回空切片，即从空区域启动）。
func loadZones(c config.Config) ([]dns.Zone, error) {
	if c.ZoneFile == "" {
		return nil, nil
	}
	return dns.LoadFile(c.ZoneFile, c.MaxZones)
}

// main 组装并启动 dnsd：解析配置 -> 载入区域 -> 建存储 -> 交给 controlplane 托管。
func main() {
	// 配置解析同时承担 -version 的「打印即退出」：exited 为真表示已处理完毕。
	c, exited := loadConfig()
	if exited {
		return
	}

	zones, err := loadZones(c)
	if err != nil {
		// 区域载入失败属致命错误：静默以空区域启动会让本该解析的域名全部落空，
		// 这种「看起来正常」的降级比直接退出更危险。
		log.Printf("载入区域失败，进程退出: %v", err)
		os.Exit(1)
	}

	// 把区域装入内存存储；之后的 HTTP 处理器只读该存储，故载入必须发生在
	// 注册路由之前（否则可能存在短暂的空区域窗口）。
	store := dns.NewStore()
	if err := store.Load(zones); err != nil {
		log.Printf("载入区域失败，进程退出: %v", err)
		os.Exit(1)
	}

	// obs 在 RegisterMetrics 回调中被赋值，随后被下面的路由闭包捕获：
	// 这即 ServerConfig.RegisterMetrics 「先于路由注册执行」约定的用途。
	// CORSAllowedOrigins 传 nil 以交由 controlplane 套用默认允许源；
	// RegisterMetrics 注册 dnsd 自有仪表（区域数 / 记录数），句柄供路由侧刷新。
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
		// 业务路由：controlplane 已挂好 /healthz、/metrics、/api/v1/version，
		// 这里只补 /api/v1/zones 系列；仪表句柄传入以便读取时刷新。
		api.RegisterRoutes(mux, api.ServerOptions{
			Store:       store,
			ZoneCount:   obs.ZoneCount,
			RecordCount: obs.RecordCount,
		})
	})
	if err != nil {
		log.Printf("dnsd 退出: %v", err)
		os.Exit(1)
	}
}
