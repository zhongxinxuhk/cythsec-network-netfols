// traffic.go - 网卡流量计数器采集。
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
type TrafficCounters struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

const sysNetDir = "/sys/class/net"

// ListTraffic 返回各网卡的流量统计。
func ListTraffic() ([]TrafficCounters, error) {
	if runtime.GOOS != "linux" {
		return []TrafficCounters{}, nil
	}
	entries, err := os.ReadDir(sysNetDir)
	if err != nil {
		return nil, err
	}
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
func readCounter(iface, stat string) uint64 {
	p := filepath.Join(iface, "statistics", stat)
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
