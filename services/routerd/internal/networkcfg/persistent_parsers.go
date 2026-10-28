package networkcfg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var profileUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func persistentMTU(p *PersistentProfile, value string) {
	n, err := strconv.Atoi(value)
	p.FieldStates["mtu"] = "unsupported"
	if err == nil && n > 0 && n <= 65536 {
		p.MTU = &n
		p.FieldStates["mtu"] = "configured"
	}
}
func persistentValues(p *PersistentProfile, field string, values []string) {
	var out []string
	valid := len(values) <= 256
	switch field {
	case "addresses":
		out = []string{}
		for _, v := range values {
			a, e := netip.ParsePrefix(v)
			if e != nil {
				valid = false
				break
			}
			out = append(out, a.String())
		}
	case "dns":
		out, valid = observedDNS(values)
	case "search":
		out, valid = observedSearch(values)
	}
	if len(values) > 256 {
		valid = false
	}
	state := "configured"
	if !valid {
		state = "unsupported"
		out = nil
	}
	p.FieldStates[field] = state
	switch field {
	case "addresses":
		p.Addresses = out
	case "dns":
		p.DNS = out
	case "search":
		p.Search = out
	}
}
func persistentRoute(p *PersistentProfile, destination, gateway, metric string) {
	if p.FieldStates["routes"] == "unsupported" {
		return
	}
	a, e := netip.ParseAddr(gateway)
	if destination == "default" && e == nil {
		destination = "::/0"
		if a.Is4() {
			destination = "0.0.0.0/0"
		}
	}
	d, de := netip.ParsePrefix(destination)
	if e != nil || de != nil || a.Is4() != d.Addr().Is4() || len(p.Routes) >= 256 {
		p.Routes = nil
		p.FieldStates["routes"] = "unsupported"
		return
	}
	var m *uint32
	if metric != "" && metric != "-1" {
		n, me := strconv.ParseUint(metric, 10, 32)
		if me != nil {
			p.Routes = nil
			p.FieldStates["routes"] = "unsupported"
			return
		}
		n32 := uint32(n)
		m = &n32
	}
	p.Routes = append(p.Routes, ConfiguredRoute{d.Masked().String(), a.String(), m})
	p.FieldStates["routes"] = "configured"
}
func stringList(raw json.RawMessage) ([]string, error) {
	var v []string
	err := json.Unmarshal(raw, &v)
	if bytes.Equal(raw, []byte("null")) {
		return nil, errNativeSchema
	}
	return v, err
}
func safeMethod(value string) string {
	switch value {
	case "auto", "manual", "disabled", "ignore", "link-local", "shared", "static", "dhcp", "dhcpv6", "none":
		return value
	}
	return "unknown"
}

// Parse only selected keyfile fields. Unsupported GLib escapes remain unknown;
// credential sections/keys are never copied into the projection.
func parseKeyfile(raw []byte, source string) (PersistentProfile, error) {
	p := newPersistentProfile("file:"+source[:12], []string{source})
	p.OriginVerified = true
	fields := map[string]string{}
	section := ""
	sections := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if section == "802-3-ethernet" {
				section = "ethernet"
			}
			if sections[section] {
				return p, errNativeSchema
			}
			sections[section] = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return p, errNativeSchema
		}
		key = strings.TrimSpace(key)
		selected := section == "ipv4" || section == "ipv6" || (section == "ethernet" && key == "mtu") || (section == "connection" && (key == "uuid" || key == "type" || key == "interface-name"))
		if !selected {
			continue
		}
		// Only retain networking properties, never credential-like extension keys.
		if section == "ipv4" || section == "ipv6" {
			selected = key == "method" || key == "dns" || key == "dns-search" || key == "gateway" || key == "route-metric" || key == "route-table" || key == "never-default" || strings.HasPrefix(key, "address") || strings.HasPrefix(key, "route") || strings.HasPrefix(key, "routing-rule")
		}
		if !selected {
			continue
		}
		full := section + "." + key
		if _, exists := fields[full]; exists {
			return p, errNativeSchema
		}
		fields[full] = strings.TrimSpace(value)
	}
	if scanner.Err() != nil || fields["connection.type"] == "" {
		return p, errNativeSchema
	}
	if uuid := fields["connection.uuid"]; profileUUID.MatchString(uuid) {
		p.Reference = "nm:" + strings.ToLower(uuid)
	}
	if fields["connection.type"] != "ethernet" && fields["connection.type"] != "802-3-ethernet" {
		for key := range p.FieldStates {
			p.FieldStates[key] = "unsupported"
		}
		return p, nil
	}
	if name := fields["connection.interface-name"]; deviceName.MatchString(name) {
		p.Device = name
		p.Binding = "declared"
	}
	if v, ok := fields["ethernet.mtu"]; ok {
		persistentMTU(&p, v)
	}
	addresses, dns, search := []string{}, []string{}, []string{}
	hasAddress, hasDNS, hasSearch := false, false, false
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, family := range []string{"ipv4", "ipv6"} {
		p.Methods[family] = "unspecified"
		if v, ok := fields[family+".method"]; ok {
			p.Methods[family] = safeMethod(v)
		}
		for _, key := range keys {
			if !strings.HasPrefix(key, family+".") {
				continue
			}
			name := strings.TrimPrefix(key, family+".")
			value := fields[key]
			switch {
			case name == "dns":
				hasDNS = true
				dns = append(dns, splitConfigList(value, ";")...)
			case name == "dns-search":
				hasSearch = true
				search = append(search, splitConfigList(value, ";")...)
			case strings.HasPrefix(name, "address"):
				hasAddress = true
				parts := strings.Split(strings.ReplaceAll(strings.TrimSuffix(value, ";"), ";", ","), ",")
				addresses = append(addresses, parts[0])
				if len(parts) > 2 {
					addresses = append(addresses, "invalid")
				}
				if len(parts) > 1 && parts[1] != "" && fields[family+".gateway"] == "" {
					persistentRoute(&p, "default", parts[1], "")
				}
			case name == "gateway":
				if value != "" {
					persistentRoute(&p, "default", value, "")
				}
			case name == "route-metric" || name == "route-table" || name == "never-default":
				if value != "" && value != "-1" && value != "0" && value != "false" {
					p.FieldStates["routes"] = "unsupported"
					p.Routes = nil
				}
			case strings.HasPrefix(name, "routing-rule"):
				p.Routes = nil
				p.FieldStates["routes"] = "unsupported"
			case strings.HasPrefix(name, "route"):
				parts := strings.Split(value, ",")
				if strings.Contains(name, "_") || len(parts) < 2 || len(parts) > 3 {
					p.FieldStates["routes"] = "unsupported"
					p.Routes = nil
					continue
				}
				metric := ""
				if len(parts) == 3 {
					metric = parts[2]
				}
				persistentRoute(&p, parts[0], parts[1], metric)
			}
		}
	}
	if hasAddress {
		persistentValues(&p, "addresses", addresses)
	}
	if hasDNS {
		persistentValues(&p, "dns", dns)
	}
	if hasSearch {
		persistentValues(&p, "search", search)
	}
	return p, nil
}
func splitConfigList(value, delimiter string) []string {
	if value == "" {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(value, delimiter), delimiter)
}

func parseNetplanProjection(raw []byte, sources []ConfigSource) ([]PersistentProfile, error) {
	var entries map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) > 64 {
		return nil, errNativeSchema
	}
	ids := []string{}
	for _, s := range sources {
		ids = append(ids, s.ID)
	}
	names := []string{}
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	profiles := []PersistentProfile{}
	for _, name := range names {
		if !observedNetworkName.MatchString(name) {
			return nil, errNativeSchema
		}
		entry := entries[name]
		p := newPersistentProfile("netplan:"+name, ids)
		device := name
		var unsupportedMatch bool
		if value, has := entry["match_supported"]; has {
			var supported bool
			if json.Unmarshal(value, &supported) != nil {
				return nil, errNativeSchema
			}
			unsupportedMatch = !supported
			if supported {
				if json.Unmarshal(entry["match_name"], &device) != nil {
					return nil, errNativeSchema
				}
			}
		}
		if !unsupportedMatch && deviceName.MatchString(device) {
			p.Device = device
			p.Binding = "declared"
		}
		if rename, has := entry["set-name"]; has {
			var n string
			if json.Unmarshal(rename, &n) != nil {
				return nil, errNativeSchema
			}
			p.Device = ""
			p.Binding = "unresolved"
		}
		for _, key := range []string{"dhcp4", "dhcp6", "accept-ra"} {
			if v, has := entry[key]; has {
				var flag bool
				if json.Unmarshal(v, &flag) != nil {
					return nil, errNativeSchema
				}
				p.Methods[key] = strconv.FormatBool(flag)
			}
		}
		if value, has := entry["mtu"]; has {
			persistentMTU(&p, string(value))
		}
		if value, has := entry["addresses"]; has {
			values, e := stringList(value)
			if e != nil {
				p.FieldStates["addresses"] = "unsupported"
			} else {
				persistentValues(&p, "addresses", values)
			}
		}
		if value, has := entry["nameservers"]; has {
			var ns map[string]json.RawMessage
			if json.Unmarshal(value, &ns) != nil {
				return nil, errNativeSchema
			}
			for field, key := range map[string]string{"dns": "addresses", "search": "search"} {
				if v, ok := ns[key]; ok {
					values, e := stringList(v)
					if e != nil {
						p.FieldStates[field] = "unsupported"
					} else {
						persistentValues(&p, field, values)
					}
				}
			}
		}
		for _, family := range []string{"gateway4", "gateway6"} {
			if v, has := entry[family]; has {
				var g string
				if json.Unmarshal(v, &g) != nil {
					return nil, errNativeSchema
				}
				persistentRoute(&p, "default", g, "")
			}
		}
		if value, has := entry["routes"]; has {
			var routes []struct {
				To, Via     string
				Metric      *uint32
				Unsupported bool `json:"unsupported_options"`
			}
			if json.Unmarshal(value, &routes) != nil || len(routes) > 256 {
				return nil, errNativeSchema
			}
			if p.FieldStates["routes"] != "unsupported" {
				if p.Routes == nil {
					p.Routes = []ConfiguredRoute{}
				}
				p.FieldStates["routes"] = "configured"
			}
			for _, route := range routes {
				if route.Unsupported {
					p.Routes = nil
					p.FieldStates["routes"] = "unsupported"
					break
				}
				metric := ""
				if route.Metric != nil {
					metric = strconv.FormatUint(uint64(*route.Metric), 10)
				}
				persistentRoute(&p, route.To, route.Via, metric)
			}
		}
		if _, has := entry["routing_policy_present"]; has {
			p.Routes = nil
			p.FieldStates["routes"] = "unsupported"
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// Tokenize only the canonical native `uci export` grammar, never execute it.
func uciLines(raw []byte) ([][]string, error) {
	lines := [][]string{}
	tokens := []string{}
	var token strings.Builder
	quote, active := false, false
	flush := func() {
		if active {
			tokens = append(tokens, token.String())
			token.Reset()
			active = false
		}
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\'':
			quote = !quote
			active = true
		case c == '\\' && !quote:
			i++
			if i >= len(raw) {
				return nil, errNativeSchema
			}
			token.WriteByte(raw[i])
			active = true
		case !quote && (c == ' ' || c == '\t' || c == '\r'):
			flush()
		case !quote && c == '\n':
			flush()
			if len(tokens) > 0 {
				lines = append(lines, tokens)
				tokens = []string{}
			}
			if len(lines) > 8192 {
				return nil, errNativeSchema
			}
		default:
			token.WriteByte(c)
			active = true
		}
	}
	if quote {
		return nil, errNativeSchema
	}
	flush()
	if len(tokens) > 0 {
		lines = append(lines, tokens)
	}
	return lines, nil
}

type uciSection struct {
	kind, name string
	fields     map[string][]string
}

func parseUCIExport(raw []byte, source string) ([]PersistentProfile, error) {
	lines, err := uciLines(raw)
	if err == nil && len(lines) == 0 {
		return nil, errNativeSchema
	}
	if err != nil {
		return nil, err
	}
	sections := []uciSection{}
	current := -1
	for _, line := range lines {
		switch line[0] {
		case "package":
			if len(line) != 2 {
				return nil, errNativeSchema
			}
		case "config":
			if len(line) < 2 || len(line) > 3 || len(sections) >= 256 {
				return nil, errNativeSchema
			}
			name := "@" + line[1] + "[" + strconv.Itoa(len(sections)) + "]"
			if len(line) == 3 {
				name = line[2]
				if !observedNetworkName.MatchString(name) {
					return nil, errNativeSchema
				}
			}
			sections = append(sections, uciSection{line[1], name, map[string][]string{}})
			current = len(sections) - 1
		case "option", "list":
			if len(line) != 3 || current < 0 {
				return nil, errNativeSchema
			}
			key := line[1]
			if sections[current].kind == "route" || sections[current].kind == "route6" {
				switch key {
				case "interface", "target", "netmask", "gateway", "metric":
				default:
					sections[current].fields["unsupported_options"] = []string{"true"}
				}
			}
			switch key {
			case "device", "ifname", "proto", "mtu", "ipaddr", "ip6addr", "netmask", "dns", "dns_search", "interface", "target", "gateway", "metric", "table", "type":
			default:
				continue
			}
			fields := sections[current].fields
			if line[0] == "option" {
				if _, exists := fields[key]; exists {
					return nil, errNativeSchema
				}
				fields[key] = []string{line[2]}
			} else {
				fields[key] = append(fields[key], line[2])
			}
		default:
			return nil, errNativeSchema
		}
	}
	profiles := []PersistentProfile{}
	index := map[string]int{}
	one := func(m map[string][]string, key string) string {
		if len(m[key]) == 1 {
			return m[key][0]
		}
		return ""
	}
	for _, section := range sections {
		if section.kind != "interface" {
			continue
		}
		if _, exists := index[section.name]; exists {
			return nil, errNativeSchema
		}
		p := newPersistentProfile("uci:"+section.name, []string{source})
		p.OriginVerified = true
		m := section.fields
		proto := safeMethod(one(m, "proto"))
		p.Methods["protocol"] = proto
		if proto != "static" && proto != "dhcp" && proto != "dhcpv6" && proto != "none" {
			for k := range p.FieldStates {
				p.FieldStates[k] = "unsupported"
			}
			index[section.name] = len(profiles)
			profiles = append(profiles, p)
			continue
		}
		device := one(m, "device")
		if device == "" {
			device = one(m, "ifname")
		}
		if deviceName.MatchString(device) && one(m, "type") != "bridge" {
			p.Device = device
			p.Binding = "declared"
		}
		if v, has := m["mtu"]; has {
			persistentMTU(&p, strings.Join(v, " "))
		}
		addresses := []string{}
		hasAddress := false
		for _, key := range []string{"ipaddr", "ip6addr"} {
			if values, has := m[key]; has {
				hasAddress = true
				for _, a := range values {
					if key == "ipaddr" && !strings.Contains(a, "/") {
						a = maskedAddress(a, one(m, "netmask"))
					}
					addresses = append(addresses, a)
				}
			}
		}
		if hasAddress {
			persistentValues(&p, "addresses", addresses)
		}
		for _, key := range []string{"dns", "dns_search"} {
			if values, has := m[key]; has {
				field := "dns"
				if key == "dns_search" {
					field = "search"
				}
				if len(values) == 1 {
					values = strings.Fields(values[0])
				}
				persistentValues(&p, field, values)
			}
		}
		index[section.name] = len(profiles)
		profiles = append(profiles, p)
	}
	for _, section := range sections {
		if section.kind != "route" && section.kind != "route6" {
			continue
		}
		m := section.fields
		i, found := index[one(m, "interface")]
		if !found {
			for i := range profiles {
				profiles[i].Routes = nil
				profiles[i].FieldStates["routes"] = "unsupported"
			}
			continue
		}
		p := &profiles[i]
		dst := one(m, "target")
		if section.kind == "route" && !strings.Contains(dst, "/") {
			dst = maskedAddress(dst, one(m, "netmask"))
		}
		if one(m, "table") != "" || one(m, "type") != "" || one(m, "unsupported_options") != "" {
			p.Routes = nil
			p.FieldStates["routes"] = "unsupported"
			continue
		}
		persistentRoute(p, dst, one(m, "gateway"), one(m, "metric"))
	}
	return profiles, nil
}
func maskedAddress(address, mask string) string {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return "invalid"
	}
	ones, bits := net.IPMask(ip).Size()
	if bits != 32 {
		return "invalid"
	}
	return address + "/" + strconv.Itoa(ones)
}
