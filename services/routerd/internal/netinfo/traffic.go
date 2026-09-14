// Package netinfo traffic.go - 网卡流量计数器采集。
// Linux：读取 /sys/class/net/<iface>/statistics/{rx_bytes,tx_bytes,rx_packets,tx_packets,...}。
// 这些是内核维护的累计计数器，零依赖、无需权限。
// 非 Linux 平台返回空表（保持跨平台可编译/可运行）。
package netinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// TrafficCounters 一张网卡的累计流量计数。
// 所有字段均为自网卡创建/内核启动以来的累计值（单调递增），非速率；
// 需要速率时由调用方在两次采样间自行求差。
type TrafficCounters struct {
	Interface string `json:"interface"`  // 接口名
	RxBytes   uint64 `json:"rx_bytes"`   // 累计接收字节数
	TxBytes   uint64 `json:"tx_bytes"`   // 累计发送字节数
	RxPackets uint64 `json:"rx_packets"` // 累计接收报文数
	TxPackets uint64 `json:"tx_packets"` // 累计发送报文数
	RxErrors  uint64 `json:"rx_errors"`  // 接收错误数
	TxErrors  uint64 `json:"tx_errors"`  // 发送错误数
	RxDropped uint64 `json:"rx_dropped"` // 接收丢弃数
	TxDropped uint64 `json:"tx_dropped"` // 发送丢弃数
}

// sysNetDir 是内核暴露所有网络接口及其统计信息的根目录。
const sysNetDir = "/sys/class/net"

// ListTraffic 返回各网卡的流量统计。
// 仅 Linux 实现；其他平台返回空表且无错误（保持跨平台可运行）。
// 单个接口的计数器缺失时以 0 呈现（readCounter 容错），不影响其余接口。
func ListTraffic() ([]TrafficCounters, error) {
	if runtime.GOOS != "linux" {
		return []TrafficCounters{}, nil
	}
	entries, err := os.ReadDir(sysNetDir)
	if err != nil {
		return nil, err
	}
	// 预分配容量：条目数即接口数上界。
	out := make([]TrafficCounters, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		ifc := sysNetDir + "/" + name
		// /sys/class/net 下的接口通常是符号链接（指向 /sys/devices/.../net/<if>），
		// DirEntry.IsDir() 对 symlink 返回 false，故不能用 IsDir 过滤。
		// 直接尝试访问 statistics 子目录，非接口条目会失败被跳过。
		if _, err := os.Stat(ifc + "/statistics"); err != nil {
			continue
		}
		out = append(out, TrafficCounters{
			Interface: name,
			RxBytes:   readCounter(ifc, "rx_bytes"),
			TxBytes:   readCounter(ifc, "tx_bytes"),
			RxPackets: readCounter(ifc, "rx_packets"),
			TxPackets: readCounter(ifc, "tx_packets"),
			RxErrors:  readCounter(ifc, "rx_errors"),
			TxErrors:  readCounter(ifc, "tx_errors"),
			RxDropped: readCounter(ifc, "rx_dropped"),
			TxDropped: readCounter(ifc, "tx_dropped"),
		})
	}
	return out, nil
}

// readCounter 读取单个统计文件，返回 u64；文件不存在或解析失败返回 0。
// 逐个文件容错而非整体失败：某些网卡可能缺少个别计数器文件，
// 缺失项填 0 比让整个 /api/v1/traffic 报错更有用。
func readCounter(iface, stat string) uint64 {
	// 路径形如 /sys/class/net/<iface>/statistics/<stat>。
	p := filepath.Join(iface, "statistics", stat)
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	// 内核以十进制文本输出，末尾带换行，需 TrimSpace 后再解析。
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
