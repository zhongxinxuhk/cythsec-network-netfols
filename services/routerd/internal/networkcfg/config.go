// Package networkcfg validates desired settings, compiles native previews, and reads
// bounded runtime observations. It never modifies operating-system networking.
package networkcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Metric      uint32 `json:"metric"`
}
type Interface struct {
	ID        string   `json:"id"`
	Device    string   `json:"device"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	DNS       []string `json:"dns"`
	Search    []string `json:"search"`
	Routes    []Route  `json:"routes"`
}
type Config struct {
	Backend    string      `json:"backend"`
	Interfaces []Interface `json:"interfaces"`
}
type Artifact struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}
type Preview struct {
	Digest    string     `json:"digest"`
	Artifacts []Artifact `json:"artifacts"`
	Stage     string     `json:"stage"`
}

var profileName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
var deviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
var domainLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func unicast(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && a.String() != "255.255.255.255"
}
func Validate(c Config) error {
	raw, _ := json.Marshal(c)
	if len(raw) > 120*1024 {
		return fmt.Errorf("配置超过120KiB限制")
	}
	if c.Backend != "netplan" && c.Backend != "networkmanager" && c.Backend != "openwrt" {
		return fmt.Errorf("选择受支持的目标管理器")
	}
	if len(c.Interfaces) < 1 || len(c.Interfaces) > 32 {
		return fmt.Errorf("接口配置数量须为1至32")
	}
	ids, devices := map[string]bool{}, map[string]bool{}
	for _, p := range c.Interfaces {
		if !profileName.MatchString(p.ID) || !deviceName.MatchString(p.Device) || p.Device == "lo" || ids[p.ID] || devices[p.Device] {
			return fmt.Errorf("接口标识或设备名称无效、重复或为回环接口")
		}
		ids[p.ID], devices[p.Device] = true, true
		if p.MTU < 576 || p.MTU > 9216 || len(p.Addresses) < 1 || len(p.Addresses) > 8 || len(p.DNS) > 6 || len(p.Search) > 6 || len(p.Routes) > 128 {
			return fmt.Errorf("MTU或接口字段数量超出范围")
		}
		addresses := map[string]bool{}
		families := map[bool]bool{}
		for _, value := range p.Addresses {
			a, err := netip.ParsePrefix(value)
			if err != nil || !unicast(a.Addr()) || (a.Addr().Is6() && p.MTU < 1280) || addresses[a.String()] {
				return fmt.Errorf("静态地址须为有效且不重复的主机IP/CIDR；IPv6的MTU至少1280")
			}
			if a.Addr().Is4() && a.Bits() < 31 {
				raw := a.Addr().As4()
				n := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				mask := uint32(0xffffffff) >> a.Bits()
				if n&mask == 0 || n&mask == mask {
					return fmt.Errorf("IPv4主机地址不能是所在子网的网络地址或广播地址")
				}
			}
			addresses[a.String()] = true
			families[a.Addr().Is4()] = true
		}
		dns := map[string]bool{}
		for _, value := range p.DNS {
			a, err := netip.ParseAddr(value)
			if err != nil || !unicast(a) || dns[a.String()] || !families[a.Is4()] {
				return fmt.Errorf("DNS须为不重复的单播IP，并有同地址族的接口地址")
			}
			dns[a.String()] = true
		}
		search := map[string]bool{}
		for _, value := range p.Search {
			if len(value) > 253 || search[strings.ToLower(value)] || value == "" {
				return fmt.Errorf("DNS搜索域无效或重复")
			}
			for _, label := range strings.Split(value, ".") {
				if !domainLabel.MatchString(label) {
					return fmt.Errorf("DNS搜索域须为有效ASCII域名")
				}
			}
			search[strings.ToLower(value)] = true
		}
		routes := map[string]bool{}
		for _, r := range p.Routes {
			dst, err := netip.ParsePrefix(r.Destination)
			gateway, gerr := netip.ParseAddr(r.Gateway)
			if err != nil || gerr != nil || dst.Addr().Is4In6() || dst != dst.Masked() || dst.Addr().IsMulticast() || dst.Addr().IsLoopback() || !unicast(gateway) || dst.Addr().Is4() != gateway.Is4() || !families[gateway.Is4()] {
				return fmt.Errorf("路由目标须为网络CIDR，下一跳须为同地址族单播IP")
			}
			reachable := gateway.Is6() && gateway.IsLinkLocalUnicast()
			for _, value := range p.Addresses {
				prefix, _ := netip.ParsePrefix(value)
				if prefix.Addr() == gateway {
					return fmt.Errorf("下一跳不能是接口自身地址")
				}
				if gateway.Is4() && prefix.Contains(gateway) && prefix.Bits() < 31 {
					raw := gateway.As4()
					n := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
					mask := uint32(0xffffffff) >> prefix.Bits()
					if n&mask == 0 || n&mask == mask {
						return fmt.Errorf("下一跳不能是子网网络地址或广播地址")
					}
				}
				reachable = reachable || prefix.Contains(gateway)
			}
			if !reachable {
				return fmt.Errorf("下一跳须在接口直连子网内")
			}
			key := fmt.Sprintf("%s/%d", dst.String(), r.Metric)
			if routes[key] {
				return fmt.Errorf("同接口、目标与Metric的路由不能重复；ECMP需专门配置")
			}
			routes[key] = true
		}
	}
	return nil
}
func Digest(c Config) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func Compile(c Config) (Preview, error) {
	if err := Validate(c); err != nil {
		return Preview{}, err
	}
	result := Preview{Digest: Digest(c), Artifacts: []Artifact{}, Stage: "validated_preview"}
	switch c.Backend {
	case "netplan":
		devices := map[string]any{}
		for _, p := range c.Interfaces {
			routes := []map[string]any{}
			for _, r := range p.Routes {
				routes = append(routes, map[string]any{"to": r.Destination, "via": r.Gateway, "metric": r.Metric})
			}
			entry := map[string]any{"dhcp4": false, "dhcp6": false, "accept-ra": false, "mtu": p.MTU, "addresses": p.Addresses, "routes": routes}
			if len(p.DNS) > 0 || len(p.Search) > 0 {
				ns := map[string]any{}
				if len(p.DNS) > 0 {
					ns["addresses"] = p.DNS
				}
				if len(p.Search) > 0 {
					ns["search"] = p.Search
				}
				entry["nameservers"] = ns
			}
			devices[p.Device] = entry
		}
		// JSON is valid YAML 1.2; no third-party YAML serializer or interpolated syntax.
		content, _ := json.MarshalIndent(map[string]any{"network": map[string]any{"version": 2, "renderer": "networkd", "ethernets": devices}}, "", "  ")
		result.Artifacts = append(result.Artifacts, Artifact{"90-cythsec.yaml", string(content) + "\n"})
	case "networkmanager":
		for _, p := range c.Interfaces {
			var b strings.Builder
			fmt.Fprintf(&b, "[connection]\nid=cythsec-%s\ntype=ethernet\ninterface-name=%s\nautoconnect=true\n\n[ethernet]\nmtu=%d\n", p.ID, p.Device, p.MTU)
			for _, v4 := range []bool{true, false} {
				family := "ipv6"
				if v4 {
					family = "ipv4"
				}
				addresses, dns := []string{}, []string{}
				for _, v := range p.Addresses {
					a, _ := netip.ParsePrefix(v)
					if a.Addr().Is4() == v4 {
						addresses = append(addresses, v)
					}
				}
				for _, v := range p.DNS {
					a, _ := netip.ParseAddr(v)
					if a.Is4() == v4 {
						dns = append(dns, v)
					}
				}
				method := "disabled"
				if len(addresses) > 0 {
					method = "manual"
				}
				fmt.Fprintf(&b, "\n[%s]\nmethod=%s\n", family, method)
				if len(addresses) == 0 {
					continue
				}
				for i, v := range addresses {
					fmt.Fprintf(&b, "address%d=%s\n", i+1, v)
				}
				fmt.Fprintf(&b, "ignore-auto-dns=true\ndns=%s\ndns-search=%s\n", strings.Join(dns, ";"), strings.Join(p.Search, ";"))
				i := 0
				for _, r := range p.Routes {
					a, _ := netip.ParsePrefix(r.Destination)
					if a.Addr().Is4() == v4 {
						i++
						fmt.Fprintf(&b, "route%d=%s,%s,%d\n", i, r.Destination, r.Gateway, r.Metric)
					}
				}
			}
			result.Artifacts = append(result.Artifacts, Artifact{"cythsec-" + p.ID + ".nmconnection", b.String()})
		}
	case "openwrt":
		var b strings.Builder
		for _, p := range c.Interfaces {
			fmt.Fprintf(&b, "config interface 'cythsec_%s'\n\toption device '%s'\n\toption proto 'static'\n\toption mtu '%d'\n\toption peerdns '0'\n", p.ID, p.Device, p.MTU)
			for _, v := range p.Addresses {
				a, _ := netip.ParsePrefix(v)
				key := "ip6addr"
				if a.Addr().Is4() {
					key = "ipaddr"
				}
				fmt.Fprintf(&b, "\tlist %s '%s'\n", key, v)
			}
			for _, v := range p.DNS {
				fmt.Fprintf(&b, "\tlist dns '%s'\n", v)
			}
			for _, v := range p.Search {
				fmt.Fprintf(&b, "\tlist dns_search '%s'\n", v)
			}
			for i, r := range p.Routes {
				a, _ := netip.ParsePrefix(r.Destination)
				kind := "route6"
				if a.Addr().Is4() {
					kind = "route"
				}
				fmt.Fprintf(&b, "\nconfig %s 'cythsec_%s_%d'\n\toption interface 'cythsec_%s'\n\toption target '%s'\n\toption gateway '%s'\n\toption metric '%d'\n", kind, p.ID, i+1, p.ID, r.Destination, r.Gateway, r.Metric)
			}
			b.WriteString("\n")
		}
		result.Artifacts = append(result.Artifacts, Artifact{"network.cythsec.uci", b.String()})
	}
	return result, nil
}
