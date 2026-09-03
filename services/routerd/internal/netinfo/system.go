// Package netinfo 采集本机网络与系统信息，供 routerd HTTP API 暴露给控制面。
// 仅使用标准库：接口/IP 用 net 包，路由表在 Linux 上解析 /proc/net/route，
// 未引入第三方 netlink 依赖，保证可离线构建、跨平台可编译。
package netinfo

import (
	"os"
	"runtime"
)

// SystemInfo 描述系统与运行时概貌。
type SystemInfo struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	PID       int    `json:"pid"`
}

// GetSystem 返回当前系统基础信息。
func GetSystem() SystemInfo {
	host, _ := os.Hostname()
	return SystemInfo{
		Hostname:  host,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		PID:       os.Getpid(),
	}
}
