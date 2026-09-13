// routes.go - 路由表采集。
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
type Route struct {
	Interface   string `json:"interface"` // 出接口名
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Mask        string `json:"mask"`
	Flags       string `json:"flags"`
	Metric      int    `json:"metric"`
	Ref         int    `json:"ref"`
	Use         int    `json:"use"`
}

// isRouteRelevant 判断一条 /proc/net/route 标志位是否该呈现给控制面。
// 过滤掉未启用的条目(RTF_UP=0x1 未置位)，保留普通路由。
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
		if len(fields) < 11 {
			continue
		}
		// fields: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		flags, _ := strconv.ParseUint(fields[3], 16, 32)
		if flags&rtfUp == 0 {
			continue // 未启用条目不暴露
		}
		dest := parseHexIP(fields[1])
		gw := parseHexIP(fields[2])
		mask := parseHexIP(fields[7])
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
	if err := sc.Err(); err != nil {
		return routes, err
	}
	return routes, nil
}
