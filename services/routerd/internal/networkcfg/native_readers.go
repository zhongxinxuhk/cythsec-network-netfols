package networkcfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var versionPattern = regexp.MustCompile(`[0-9]+(?:\.[0-9]+){0,3}`)
var activeNMPath = regexp.MustCompile(`^/org/freedesktop/NetworkManager/ActiveConnection/[0-9]+$`)
var observedNetworkName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
var errNativeSchema = errors.New("unsupported native schema")

func stringSet(values []string) []string {
	m := map[string]bool{}
	for _, v := range values {
		m[v] = true
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func observedDNS(values []string) ([]string, bool) {
	out := []string{}
	for _, v := range values {
		a, e := netip.ParseAddr(v)
		if e != nil || a.IsUnspecified() || a.IsMulticast() {
			return nil, false
		}
		out = append(out, a.Unmap().String())
	}
	return stringSet(out), true
}
func observedSearch(values []string) ([]string, bool) {
	out := []string{}
	for _, v := range values {
		v = strings.TrimSuffix(strings.ToLower(v), ".")
		if len(v) > 253 || v == "" {
			return nil, false
		}
		for _, p := range strings.Split(v, ".") {
			if !domainLabel.MatchString(p) {
				return nil, false
			}
		}
		out = append(out, v)
	}
	return stringSet(out), true
}
func nmUnescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i >= len(s) || (s[i] != '\\' && s[i] != ':') {
				return "", errNativeSchema
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}
func parseNM(raw []byte) ([]nativeInterface, error) {
	result := []nativeInterface{}
	var current map[string]string
	seen := map[string]bool{}
	flush := func() error {
		if current == nil {
			return nil
		}
		name := current["GENERAL.DEVICE"]
		if !deviceName.MatchString(name) || seen[name] || len(seen) >= 512 {
			return errNativeSchema
		}
		seen[name] = true
		stateFields := strings.Fields(current["GENERAL.STATE"])
		if len(stateFields) == 0 {
			return errNativeSchema
		}
		state, e := strconv.Atoi(stateFields[0])
		if e != nil {
			return errNativeSchema
		}
		if state < 20 || state > 120 {
			return nil
		}
		ref := current["GENERAL.CON-PATH"]
		if ref == "--" {
			ref = ""
		}
		if ref != "" && (len(ref) > 160 || !activeNMPath.MatchString(ref)) {
			return errNativeSchema
		}
		p := nativeInterface{Device: name, Owner: Owner{"networkmanager", ref, "nmcli"}}
		dns, search := []string{}, []string{}
		ipSection := false
		dnsSeen, searchSeen := false, false
		for key, value := range current {
			if strings.HasPrefix(key, "IP4.") || strings.HasPrefix(key, "IP6.") {
				ipSection = true
			}
			if strings.HasPrefix(key, "IP4.DNS[") || strings.HasPrefix(key, "IP6.DNS[") {
				dnsSeen = true
			}
			if strings.HasPrefix(key, "IP4.DOMAIN[") || strings.HasPrefix(key, "IP6.DOMAIN[") || strings.HasPrefix(key, "IP4.SEARCHES[") || strings.HasPrefix(key, "IP6.SEARCHES[") {
				searchSeen = true
			}
			if value == "" || value == "--" {
				continue
			}
			if strings.HasPrefix(key, "IP4.DNS[") || strings.HasPrefix(key, "IP6.DNS[") {
				dns = append(dns, value)
			}
			if strings.HasPrefix(key, "IP4.DOMAIN[") || strings.HasPrefix(key, "IP6.DOMAIN[") || strings.HasPrefix(key, "IP4.SEARCHES[") || strings.HasPrefix(key, "IP6.SEARCHES[") {
				search = append(search, value)
			}
		}
		if state == 100 && ipSection {
			p.DNS, p.DNSKnown = observedDNS(dns)
			p.Search, p.SearchKnown = observedSearch(search)
			p.DNSKnown = p.DNSKnown && dnsSeen
			p.SearchKnown = p.SearchKnown && searchSeen
		}
		result = append(result, p)
		return nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errNativeSchema
		}
		value, e := nmUnescape(strings.TrimSpace(value))
		if e != nil {
			return nil, e
		}
		if key == "GENERAL.DEVICE" {
			if e = flush(); e != nil {
				return nil, e
			}
			current = map[string]string{}
		}
		if current == nil {
			return nil, errNativeSchema
		}
		if _, exists := current[key]; exists {
			return nil, errNativeSchema
		}
		current[key] = value
		if len(result) > 512 {
			return nil, errNativeSchema
		}
	}
	if e := flush(); e != nil {
		return nil, e
	}
	return result, nil
}
func jsonIP(raw json.RawMessage) (string, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		a, e := netip.ParseAddr(text)
		if e != nil {
			return "", errNativeSchema
		}
		return a.Unmap().String(), nil
	}
	var numbers []uint8
	if json.Unmarshal(raw, &numbers) != nil {
		return "", errNativeSchema
	}
	a, ok := netip.AddrFromSlice(numbers)
	if !ok {
		return "", errNativeSchema
	}
	return a.Unmap().String(), nil
}
func parseNetworkd(raw []byte) ([]nativeInterface, error) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, errNativeSchema
	}
	if _, wrapped := envelope["type"]; wrapped {
		var reply struct {
			Type string   `json:"type"`
			Data []string `json:"data"`
		}
		if json.Unmarshal(raw, &reply) != nil || reply.Type != "s" || len(reply.Data) != 1 {
			return nil, errNativeSchema
		}
		var decoded map[string]json.RawMessage
		if json.Unmarshal([]byte(reply.Data[0]), &decoded) != nil {
			return nil, errNativeSchema
		}
		envelope = decoded
	}
	items, exists := envelope["Interfaces"]
	if !exists {
		return nil, errNativeSchema
	}
	var links []struct {
		Name                string
		Index               int
		MTU                 int
		AdministrativeState string
		NetworkFile         string
		DNS                 []struct {
			Address        json.RawMessage
			InterfaceIndex int
		}
		SearchDomains []struct{ Domain string }
	}
	if bytes.Equal(bytes.TrimSpace(items), []byte("null")) || json.Unmarshal(items, &links) != nil || len(links) > 512 {
		return nil, errNativeSchema
	}
	result := []nativeInterface{}
	seen := map[string]bool{}
	for _, link := range links {
		if !deviceName.MatchString(link.Name) || seen[link.Name] || link.Index <= 0 || link.MTU <= 0 {
			return nil, errNativeSchema
		}
		seen[link.Name] = true
		if len(link.NetworkFile) > 4096 {
			return nil, errNativeSchema
		}
		if link.NetworkFile == "" || link.AdministrativeState == "unmanaged" {
			continue
		}
		if link.AdministrativeState != "configured" && link.AdministrativeState != "configuring" {
			continue
		}
		backend := "networkd"
		p := nativeInterface{Device: link.Name, Owner: Owner{backend, filepath.Base(link.NetworkFile), "networkd_dbus"}}
		dns, search := []string{}, []string{}
		if len(link.DNS) > 256 || len(link.SearchDomains) > 256 {
			return nil, errNativeSchema
		}
		for _, server := range link.DNS {
			value, e := jsonIP(server.Address)
			if e != nil {
				return nil, e
			}
			if a, err := netip.ParseAddr(value); err == nil && a.Is6() && a.IsLinkLocalUnicast() && server.InterfaceIndex > 0 {
				value = a.WithZone(strconv.Itoa(server.InterfaceIndex)).String()
			}
			dns = append(dns, value)
		}
		for _, domain := range link.SearchDomains {
			search = append(search, domain.Domain)
		}
		if link.DNS != nil {
			p.DNS, p.DNSKnown = observedDNS(dns)
		}
		if link.SearchDomains != nil {
			p.Search, p.SearchKnown = observedSearch(search)
		}
		result = append(result, p)
	}
	return result, nil
}
func parseOpenWrt(raw []byte) ([]nativeInterface, error) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, errNativeSchema
	}
	items, exists := envelope["interface"]
	if !exists || bytes.Equal(bytes.TrimSpace(items), []byte("null")) {
		return nil, errNativeSchema
	}
	var links []struct {
		Interface string   `json:"interface"`
		Device    string   `json:"device"`
		L3Device  string   `json:"l3_device"`
		Proto     string   `json:"proto"`
		DNS       []string `json:"dns-server"`
		Search    []string `json:"dns-search"`
	}
	if json.Unmarshal(items, &links) != nil || len(links) > 512 {
		return nil, errNativeSchema
	}
	result := []nativeInterface{}
	for _, link := range links {
		if !observedNetworkName.MatchString(link.Interface) || link.Proto == "" {
			return nil, errNativeSchema
		}
		device := link.L3Device
		if device == "" {
			device = link.Device
		}
		if device == "" {
			continue
		}
		if !deviceName.MatchString(device) {
			return nil, errNativeSchema
		}
		p := nativeInterface{Device: device, Owner: Owner{"openwrt", link.Interface, "ubus"}}
		// Presence is required: omitted arrays are unknown, explicit [] is empty.
		if link.DNS != nil {
			p.DNS, p.DNSKnown = observedDNS(link.DNS)
		}
		if link.Search != nil {
			p.Search, p.SearchKnown = observedSearch(link.Search)
		}
		result = append(result, p)
		if link.Device != "" && link.Device != device && deviceName.MatchString(link.Device) {
			result = append(result, nativeInterface{Device: link.Device, Owner: Owner{"openwrt", link.Interface + " (L3:" + device + ")", "ubus"}, Restriction: "indirect_l3_path"})
		}
	}
	return result, nil
}
func parseIPRoutes(raw []byte, v4 bool) (map[string][]Route, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' {
		return nil, errNativeSchema
	}
	var items []struct {
		Destination string          `json:"dst"`
		Gateway     string          `json:"gateway"`
		Device      string          `json:"dev"`
		Metric      uint32          `json:"metric"`
		Type        string          `json:"type"`
		NextHops    json.RawMessage `json:"nexthops"`
		Encap       json.RawMessage `json:"encap"`
		Via         json.RawMessage `json:"via"`
		NHID        json.RawMessage `json:"nhid"`
		Flags       []string        `json:"flags"`
	}
	if json.Unmarshal(raw, &items) != nil || len(items) > 4096 {
		return nil, errNativeSchema
	}
	out := map[string][]Route{}
	for _, r := range items {
		if len(r.Encap) > 0 || len(r.Via) > 0 || len(r.NHID) > 0 || len(r.Flags) > 0 {
			return nil, errNativeSchema
		}
		if len(r.NextHops) > 0 && !bytes.Equal(r.NextHops, []byte("null")) {
			return nil, errNativeSchema
		}
		if r.Type != "" && r.Type != "unicast" {
			return nil, errNativeSchema
		}
		if !deviceName.MatchString(r.Device) {
			return nil, errNativeSchema
		}
		dst := r.Destination
		if dst == "default" {
			dst = "::/0"
			if v4 {
				dst = "0.0.0.0/0"
			}
		}
		prefix, e := netip.ParsePrefix(dst)
		if e != nil {
			if address, err := netip.ParseAddr(dst); err == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
				e = nil
			}
		}
		if e != nil || prefix != prefix.Masked() || prefix.Addr().Is4() != v4 {
			return nil, errNativeSchema
		}
		gateway := r.Gateway
		if gateway != "" {
			a, e := netip.ParseAddr(gateway)
			if e != nil || a.Is4() != v4 {
				return nil, errNativeSchema
			}
			gateway = a.String()
		}
		out[r.Device] = append(out[r.Device], Route{prefix.String(), gateway, r.Metric})
	}
	return out, nil
}
func routeStrings(routes []Route) []string {
	out := []string{}
	for _, r := range routes {
		out = append(out, fmt.Sprintf("%s via %s metric %d", r.Destination, r.Gateway, r.Metric))
	}
	return stringSet(out)
}
