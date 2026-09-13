// Package versioninfo 提供 cythsec 各 Go 服务统一的版本信息。
//
// 设计目标：替代此前各服务 `cmd/*/main.go` 里各自声明的 `var version = "dev"`，
// 使版本 / commit / 构建时间可由构建脚本以统一路径注入：
//
//	go build -ldflags "\
//	  -X cythsec/services/pkg/versioninfo.Version=$(cat VERSION) \
//	  -X cythsec/services/pkg/versioninfo.Commit=$(git rev-parse --short HEAD) \
//	  -X cythsec/services/pkg/versioninfo.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// 未注入时三项均保留占位值（"dev" / "unknown"），便于本地直接 `go run` 调试。
package versioninfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// 以下变量由构建脚本通过 -ldflags -X 注入；默认值用于未注入的本地调试场景。
var (
	// Version 语义化版本号，取自仓库根 VERSION 文件。
	Version = "dev"
	// Commit 构建时的 git 短哈希（未注入为 "unknown"）。
	Commit = "unknown"
	// BuildTime 构建时刻（UTC，RFC3339 格式；未注入为 "unknown"）。
	BuildTime = "unknown"
)

// Info 是对外暴露的版本信息快照，字段均为字符串以直接序列化为 JSON。
type Info struct {
	Version   string `json:"version"`    // 版本号，如 "0.1.0"
	Commit    string `json:"commit"`     // git 短哈希
	BuildTime string `json:"build_time"` // 构建时间（UTC, RFC3339）
	GoVersion string `json:"go_version"` // 编译期 Go 版本，如 "go1.26.2"
	OS        string `json:"os"`         // 目标操作系统
	Arch      string `json:"arch"`       // 目标架构
}

// Get 返回当前二进制的版本信息。
//
// GoVersion 优先取自 build info（即真正的编译工具链版本），回退到 runtime.Version()；
// 两者在常规构建下一致，但在 `go run` 或交叉编译场景下 build info 更准确。
func Get() Info {
	return Info{
		Version:   nonEmpty(Version, "dev"),
		Commit:    nonEmpty(Commit, "unknown"),
		BuildTime: nonEmpty(BuildTime, "unknown"),
		GoVersion: goVersion(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String 返回单行版本摘要，供 `-version` flag 与启动日志使用。
// 形如：`0.1.0 (commit abc1234, built 2026-09-14T02:00:00Z, go1.26.2 darwin/arm64)`
func String() string {
	i := Get()
	var b strings.Builder
	b.WriteString(i.Version)
	b.WriteString(" (commit ")
	b.WriteString(i.Commit)
	b.WriteString(", built ")
	b.WriteString(i.BuildTime)
	b.WriteString(", ")
	b.WriteString(i.GoVersion)
	b.WriteByte(' ')
	b.WriteString(i.OS)
	b.WriteByte('/')
	b.WriteString(i.Arch)
	b.WriteByte(')')
	return b.String()
}

// goVersion 取编译期 Go 版本：优先 build info 的 GoVersion 字段，
// 缺失时回退到 runtime.Version()。
func goVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.GoVersion != "" {
		return bi.GoVersion
	}
	return runtime.Version()
}

// nonEmpty 在 s 为空串时返回 fallback。
func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
