// Package netinfo Package net info Package net info 采集本机网络与系统信息，供 routed HTTP API 暴露给控制面。
// 仅使用标准库：接口/IP 用 net 包，路由表在 Linux 上解析 /proc/net/route，
// 未引入第三方 netlink 依赖，保证可离线构建、跨平台可编译。
package netinfo

import (
	"os"
	"runtime"
)

// SystemInfo 描述系统与运行时概貌。
// 字段均为进程启动后可确定的静态值，JSON 标签供 Web Console / 控制面直接消费。
type SystemInfo struct {
	Hostname  string `json:"hostname"`   // 主机名（os.Hostname；取不到时为空串）
	OS        string `json:"os"`         // 运行时操作系统，如 linux / darwin
	Arch      string `json:"arch"`       // 目标架构，如 amd64 / arm64
	GoVersion string `json:"go_version"` // 构建所用 Go 版本，如 go1.22.0
	PID       int    `json:"pid"`        // 当前进程 PID
}

// GetSystem 返回当前系统基础信息。
// 全部取自标准库的运行时/进程信息，不涉及 I/O，故无错误返回。
func GetSystem() SystemInfo {
	// 故意忽略 os.Hostname 的错误：主机名取不到属边缘情况，用空串退化即可，
	// 不值得让整个 /api/v1/system 失败（其余字段仍然有效）。
	host, _ := os.Hostname()
	return SystemInfo{
		Hostname:  host,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		PID:       os.Getpid(),
	}
}
