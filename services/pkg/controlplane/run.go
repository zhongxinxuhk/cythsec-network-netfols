// 本文件提供控制面服务的启动骨架：日志 / 指标装配、HTTP 监听与优雅关闭。
//
// 各服务的 main() 因此只需做两件事：解析自身 flag，然后调用 Run。
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cythsec/services/pkg/logging"
	"cythsec/services/pkg/metrics"
	"cythsec/services/pkg/versioninfo"
)

// defaultShutdownTimeout 是未显式配置时的优雅关闭超时。
const defaultShutdownTimeout = 10 * time.Second

// readHeaderTimeout 限制读取请求头的时长，缓解 Slowloris 类慢速攻击。
const readHeaderTimeout = 5 * time.Second

// ServerConfig 是控制面服务的启动参数。
//
// 各字段的零值均映射到合理默认值，便于最小化启动。
type ServerConfig struct {
	// Service 是服务名，作为日志固定字段与 /healthz 响应内容。
	Service string
	// Addr 是 HTTP 监听地址，如 ":8080" 或 "127.0.0.1:8080"。
	Addr string
	// ShutdownTimeout 是优雅关闭超时；≤0 时取 10s。
	ShutdownTimeout time.Duration
	// LogLevel 是日志级别：debug / info / warn / error。
	LogLevel string
	// LogFormat 是日志格式：json / text。
	LogFormat string
	// MetricsEnabled 为 false 时不暴露 GET /metrics（默认为 true）。
	MetricsEnabled bool
	// CORSAllowedOrigins 允许跨域的源列表；为空时使用 DefaultCORSOrigins。
	CORSAllowedOrigins []string
	// RegisterMetrics 可选：在指标注册表创建后注册服务自有的业务指标，
	// 返回非 nil 时启动失败。执行顺序早于路由注册，因此可在此保存指标句柄，
	// 供随后在 register 中注册的处理器闭包使用。
	RegisterMetrics func(reg *metrics.Registry) error
	// Logger 可选：注入已有日志器（测试或宿主已初始化日志时使用）。
	Logger *slog.Logger
}

// Runtime 汇总控制面服务运行所需的已装配组件。
type Runtime struct {
	// Logger 是已就绪的结构化日志器，同时已设为 slog 全局默认。
	Logger *slog.Logger
	// Registry 是指标注册表（含 HTTP 通用指标与 Go 运行时指标）。
	Registry *metrics.Registry
	// Metrics 是聚合的 HTTP 指标。
	Metrics *metrics.HTTPMetrics
	// Handler 是组装完成的 HTTP handler（基础端点 + 业务路由 + 中间件栈）。
	Handler http.Handler

	refresh func()
}

// NewRuntime 装配日志器、指标与 HTTP handler。
//
// register 用于注册各服务自身的业务路由，可为 nil。
func NewRuntime(cfg ServerConfig, register func(*http.ServeMux)) (*Runtime, error) {
	logger := cfg.Logger
	if logger == nil {
		var err error
		logger, err = logging.New(logging.Options{
			Level:   cfg.LogLevel,
			Format:  cfg.LogFormat,
			Service: cfg.Service,
		})
		if err != nil {
			return nil, fmt.Errorf("初始化日志失败: %w", err)
		}
	}
	logging.SetDefault(logger)

	registry := metrics.NewRegistry()
	refresh := metrics.RegisterGoCollector(registry)
	httpMetrics, err := metrics.NewHTTPMetrics(registry)
	if err != nil {
		return nil, fmt.Errorf("初始化指标失败: %w", err)
	}

	// 业务指标必须在注册路由之前登记完，处理器才能安全引用其句柄。
	if cfg.RegisterMetrics != nil {
		if err := cfg.RegisterMetrics(registry); err != nil {
			return nil, fmt.Errorf("注册业务指标失败: %w", err)
		}
	}

	handler := NewHandler(Options{
		Service:               cfg.Service,
		CORSAllowedOrigins:    cfg.CORSAllowedOrigins,
		Logger:                logger,
		Metrics:               httpMetrics,
		Registry:              registry,
		RuntimeMetricsRefresh: refresh,
		DisableMetrics:        !cfg.MetricsEnabled,
	}, register)

	return &Runtime{
		Logger:   logger,
		Registry: registry,
		Metrics:  httpMetrics,
		Handler:  handler,
		refresh:  refresh,
	}, nil
}

// Serve 在 Addr 上监听并提供服务，阻塞直至收到 SIGINT / SIGTERM，
// 随后在 ShutdownTimeout 窗口内等待在途请求完成后返回。
//
// 正常关闭返回 nil；监听或关闭出错返回对应 error。
func (rt *Runtime) Serve(cfg ServerConfig) error {
	timeout := cfg.ShutdownTimeout
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           rt.Handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		sig := <-stop
		rt.Logger.Info("收到关闭信号，开始优雅关闭",
			"signal", sig.String(), "timeout", timeout.String())
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			rt.Logger.Error("优雅关闭出错", "err", err)
		}
	}()

	rt.Logger.Info(cfg.Service+" 启动",
		"version", versioninfo.Version,
		"commit", versioninfo.Commit,
		"build_time", versioninfo.BuildTime,
		"go_version", versioninfo.Get().GoVersion,
		"addr", cfg.Addr,
		"log_level", cfg.LogLevel,
		"log_format", cfg.LogFormat,
		"metrics_enabled", cfg.MetricsEnabled,
	)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("监听 %s 失败: %w", cfg.Addr, err)
	}
	rt.Logger.Info(cfg.Service + " 已退出")
	return nil
}

// Run 是 NewRuntime + Serve 的便捷组合，供各服务 main() 一行调用。
func Run(cfg ServerConfig, register func(*http.ServeMux)) error {
	rt, err := NewRuntime(cfg, register)
	if err != nil {
		return err
	}
	return rt.Serve(cfg)
}

// PrintVersion 打印服务名与版本信息，供 -version flag 使用。
//
// 此时日志器通常尚未构造，故直接用标准 log 输出到 stderr。
func PrintVersion(service string) {
	log.Printf("%s %s", service, versioninfo.String())
}
