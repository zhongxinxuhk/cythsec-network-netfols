// Package logging 提供 cythsec 各 Go 服务统一的结构化日志。
//
// 基于标准库 log/slog，默认输出 JSON（便于 `jq` / 日志采集器解析），
// 开发时可用 text 格式获得更易读的控制台输出。
//
// 用法：
//
//	logger, err := logging.New(logging.Options{Level: "info", Format: "json", Service: "routerd"})
//	...
//	handler := httpx.Chain(mux, logging.Middleware(logger), metricsMW)
//
// 每条访问日志形如：
//
//	{"time":"2026-09-14T02:00:00.123Z","level":"INFO","msg":"http",
//	 "service":"routerd","request_id":"a1b2...","method":"GET",
//	 "route":"/healthz","status":200,"bytes":42,"duration_ms":0.123}
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Options 配置日志器。
type Options struct {
	// Level 日志级别：debug / info / warn / error（大小写不敏感）。空值默认 info。
	Level string
	// Format 输出格式：json / text。空值默认 json。
	Format string
	// Service 服务名，作为固定字段 service 附加到每条日志。
	Service string
	// Output 输出目标；nil 表示 os.Stderr。
	Output io.Writer
	// AddSource 是否附加源码位置（开发调试用，生产建议关闭）。
	AddSource bool
}

// ParseLevel 解析日志级别字符串，大小写不敏感。
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, fmt.Errorf("未知日志级别: %q（可选 debug/info/warn/error）", s)
}

// New 按选项构造日志器。
func New(opts Options) (*slog.Logger, error) {
	lv, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	w := opts.Output
	if w == nil {
		w = os.Stderr
	}

	hOpts := &slog.HandlerOptions{Level: lv, AddSource: opts.AddSource}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", "json":
		h = slog.NewJSONHandler(w, hOpts)
	case "text":
		h = slog.NewTextHandler(w, hOpts)
	default:
		return nil, fmt.Errorf("未知日志格式: %q（可选 json/text）", opts.Format)
	}

	logger := slog.New(h)
	if opts.Service != "" {
		logger = logger.With(slog.String("service", opts.Service))
	}
	return logger, nil
}

// loggerCtxKey 是日志器在上下文中的键类型。
type loggerCtxKey struct{}

// WithLogger 把日志器放入上下文。
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerCtxKey{}, l)
}

// FromContext 取回上下文中的日志器；不存在时返回 slog.Default()。
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerCtxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// SetDefault 同时设置 slog 全局默认日志器（影响未显式传 logger 的库代码）。
func SetDefault(l *slog.Logger) {
	slog.SetDefault(l)
}
