// Package netinfo routes.go - 路由表采集。
// Linux：解析 /proc/net/route（IPv4），这是内核导出的经典路由表，无需 netlink 权限。
// 非 Linux 平台返回空表（保持跨平台可编译与可运行）。
package netinfo

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Route 一条 IPv4 路由。
// Destination / Gateway / Mask 均以点分十进制呈现（由 parseHexIP 从内核的
// little-endian 十六进制转换而来）；Flags 保留内核原始十六进制字符串。
type Route struct {
	Interface   string `json:"interface"`   // 出接口名，如 eth0
	Destination string `json:"destination"` // 目的网段
	Gateway     string `json:"gateway"`     // 下一跳网关
	Mask        string `json:"mask"`        // 子网掩码
	Flags       string `json:"flags"`       // 内核标志位原始值（十六进制串）
	Metric      int    `json:"metric"`      // 路由度量值
	Ref         int    `json:"ref"`         // 引用计数（内核 RefCnt 列）
	Use         int    `json:"use"`         // 使用计数
}

// rtfUp 是 /proc/net/route 中标志位的「路由已启用」位（RTF_UP=0x1）。
// 未置位表示该条目未生效，不呈现给控制面。
const rtfUp = 0x1

// parseHexIP 把 little-endian 十六进制主机序转成点分十进制 IPv4。
func parseHexIP(h string) string {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return ""
	}
	ip := make(net.IP, 4)
	// /proc/net/route 以 little-endian 存储地址（第一字节在最低位）。
	ip[0] = byte(v)
	ip[1] = byte(v >> 8)
	ip[2] = byte(v >> 16)
	ip[3] = byte(v >> 24)
	return ip.String()
}

// ListRoutes 返回当前 IPv4 路由表。
// 仅 Linux 实现；其他平台返回空表且无错误（保证跨平台可运行）。
// 扫描中途出错时返回「已解析的部分路由 + 该错误」，便于调用方按需降级。
func ListRoutes() ([]Route, error) {
	if runtime.GOOS != "linux" {
		return []Route{}, nil
	}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var routes []Route
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first { // 跳过表头 Iface Destination Gateway Flags RefCnt Use Metric ...
			first = false
			continue
		}
		fields := strings.Fields(line)
		// 少于 11 列视为异常行（正常行含 Mask/MTU/Window/IRTT 等），跳过。
		if len(fields) < 11 {
			continue
		}
		// fields: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		flags, _ := strconv.ParseUint(fields[3], 16, 32)
		if flags&rtfUp == 0 {
			continue // 未启用条目不暴露
		}
		dest := parseHexIP(fields[1]) // 目的网段
		gw := parseHexIP(fields[2])   // 网关
		mask := parseHexIP(fields[7]) // 掩码在第 8 列
		// 数值列解析失败时忽略错误并用零值：单列异常不应让整表失败。
		metric, _ := strconv.Atoi(fields[6])
		ref, _ := strconv.Atoi(fields[4])
		use, _ := strconv.Atoi(fields[5])
		routes = append(routes, Route{
			Interface:   fields[0],
			Destination: dest,
			Gateway:     gw,
			Mask:        mask,
			Flags:       fields[3],
			Metric:      metric,
			Ref:         ref,
			Use:         use,
		})
	}
	// 扫描过程中的 I/O / 超长行等错误在此返回（仍带上已解析的路由）。
	if err := sc.Err(); err != nil {
		return routes, err
	}
	return routes, nil
}
