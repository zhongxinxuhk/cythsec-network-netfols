// interfaces.go - 网卡 / IP / 接口状态采集。
package netinfo

import (
	"net"
	"strconv"
	"strings"
)

// InterfaceAddr 一个网卡上绑定的一个地址。
type InterfaceAddr struct {
	IP         string `json:"ip"`
	CIDR       string `json:"cidr"`
	Scope      string `json:"scope,omitempty"` // global / link / host
	IsLoopback bool   `json:"is_loopback"`
}

// InterfaceInfo 一张网卡的汇总信息（含状态与地址）。
type InterfaceInfo struct {
	Name         string          `json:"name"`
	Index        int             `json:"index"`
	MTU          int             `json:"mtu"`
	MAC          string          `json:"mac"`
	Flags        []string        `json:"flags"`
	Up           bool            `json:"up"`
	Running      bool            `json:"running"`
	Loopback     bool            `json:"loopback"`
	Broadcast    bool            `json:"broadcast"`
	Multicast    bool            `json:"multicast"`
	PointToPoint bool            `json:"point_to_point"`
	Addrs        []InterfaceAddr `json:"addresses"`
}

func ifFlagSet(f net.Flags, bit net.Flags) bool { return f&bit != 0 }

// collectAddr 将 net.Addr 归一化为 InterfaceAddr。
func collectAddr(a net.Addr) InterfaceAddr {
	ipNet, ok := a.(*net.IPNet)
	if !ok {
		// 某些平台返回 *net.IPAddr
		if ip, ok := a.(*net.IPAddr); ok {
			prefix := 32
			if ip.IP.To4() == nil {
				prefix = 128
			}
			return InterfaceAddr{
				IP:         ip.IP.String(),
				CIDR:       ip.IP.String() + "/" + strconv.Itoa(prefix),
				Scope:      addrScope(ip.IP),
				IsLoopback: ip.IP.IsLoopback(),
			}
		}
		return InterfaceAddr{IP: a.String()}
	}
	return InterfaceAddr{
		IP:         ipNet.IP.String(),
		CIDR:       ipNet.String(),
		IsLoopback: ipNet.IP.IsLoopback(),
		Scope:      addrScope(ipNet.IP),
	}
}

func addrScope(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "host"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link"
	case ip.IsGlobalUnicast():
		return "global"
	default:
		return ""
	}
}

// ListInterfaces 返回本机全部网络接口（含地址与状态）。
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(ifaces))
	for _, ifc := range ifaces {
		addrs, aerr := ifc.Addrs()
		// 部分平台（如 Windows 的 loopback 伪接口）MTU 未定义时返回 -1，
		// 归一化为 0 以便 JSON 消费者语义清晰（0 = 不适用）。
		mtu := ifc.MTU
		if mtu < 0 {
			mtu = 0
		}
		info := InterfaceInfo{
			Name:         ifc.Name,
			Index:        ifc.Index,
			MTU:          mtu,
			MAC:          ifc.HardwareAddr.String(),
			Up:           ifFlagSet(ifc.Flags, net.FlagUp),
			Running:      ifFlagSet(ifc.Flags, net.FlagRunning),
			Loopback:     ifFlagSet(ifc.Flags, net.FlagLoopback),
			Broadcast:    ifFlagSet(ifc.Flags, net.FlagBroadcast),
			Multicast:    ifFlagSet(ifc.Flags, net.FlagMulticast),
			PointToPoint: ifFlagSet(ifc.Flags, net.FlagPointToPoint),
			Addrs:        []InterfaceAddr{},
		}
		var fl []string
		if info.Up {
			fl = append(fl, "up")
		}
		if info.Running {
			fl = append(fl, "running")
		}
		if info.Loopback {
			fl = append(fl, "loopback")
		}
		if info.Broadcast {
			fl = append(fl, "broadcast")
		}
		if info.Multicast {
			fl = append(fl, "multicast")
		}
		info.Flags = fl

		if aerr == nil {
			for _, a := range addrs {
				if strings.Contains(a.String(), "<nil>") {
					continue
				}
				info.Addrs = append(info.Addrs, collectAddr(a))
			}
		}
		out = append(out, info)
	}
	return out, nil
}
