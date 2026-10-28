package networkcfg

import (
	"context"
	"reflect"
	"strings"
	"time"
)

const loadedFields = "connection.uuid,connection.type,connection.interface-name,802-3-ethernet.mtu,ipv4.method,ipv6.method,ipv4.addresses,ipv6.addresses,ipv4.dns,ipv6.dns,ipv4.dns-search,ipv6.dns-search"

var comparedFields = []string{"device", "mtu", "ipv4_method", "ipv6_method", "addresses", "dns", "search"}

type LoadedField struct {
	Field  string `json:"field"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Source any    `json:"source"`
	Loaded any    `json:"loaded"`
}
type LoadedComparison struct {
	State      string        `json:"state"`
	Scope      string        `json:"scope"`
	ObservedAt time.Time     `json:"observed_at"`
	Diagnostic string        `json:"diagnostic"`
	Fields     []LoadedField `json:"fields"`
}

func (p *PersistentReader) compareLoadedSettings(ctx context.Context, r *PersistentInspection) {
	args := []string{"-t", "-m", "multiline", "-f", loadedFields, "connection", "show"}
	requested := map[string]bool{}
	for i := range r.Profiles {
		profile := &r.Profiles[i]
		c := &LoadedComparison{State: "not_checked", Scope: "nm_profile_scalar_and_sets", ObservedAt: time.Now().UTC(), Diagnostic: "reference_not_matched", Fields: []LoadedField{}}
		profile.Loaded = c
		if p.platform != "linux" {
			c.State, c.Diagnostic = "unsupported", "unsupported_platform"
		} else if r.Backend != "networkmanager" {
			c.Diagnostic = "backend_not_supported"
		} else if uuid, ok := strings.CutPrefix(profile.Reference, "nm:"); ok && profileUUID.MatchString(uuid) && profile.LoadReference == "matched" {
			c.State, c.Diagnostic = "unavailable", "settings_unavailable"
			uuid = strings.ToLower(uuid)
			if !requested[uuid] {
				requested[uuid] = true
				args = append(args, "uuid", uuid)
			}
		}
	}
	if len(requested) == 0 {
		return
	}
	// One bounded batch covers the existing 64-file inventory, not one process
	// per profile. Never fall back to a broad settings/secret query.
	raw, err := p.execute(ctx, "nmcli", args, "", "")
	var loaded map[string]PersistentProfile
	diagnostic := "settings_unavailable"
	if err == nil {
		loaded, err = parseLoadedSettings(raw, requested)
		diagnostic = "settings_schema_unsupported"
	}
	for i := range r.Profiles {
		profile := &r.Profiles[i]
		c := profile.Loaded
		if c.State != "unavailable" {
			continue
		}
		if err != nil {
			c.Diagnostic = diagnostic
			continue
		}
		settings, ok := loaded[strings.ToLower(strings.TrimPrefix(profile.Reference, "nm:"))]
		if !ok {
			c.Diagnostic = "profile_not_observed"
			continue
		}
		c.State, c.Diagnostic, c.ObservedAt = "partial", "partial_scope_not_full_sync", time.Now().UTC()
		for _, name := range comparedFields {
			source, sourceKnown := loadedFieldValue(*profile, name)
			value, loadedKnown := loadedFieldValue(settings, name)
			f := LoadedField{Field: name, Source: source, Loaded: value, State: "unknown", Reason: "source_unset_or_unsupported"}
			if !loadedKnown {
				f.Reason = "loaded_field_unsupported"
			} else if sourceKnown {
				f.State, f.Reason = "same", "compared"
				if !reflect.DeepEqual(source, value) {
					f.State = "different"
					c.State = "different"
				}
			}
			c.Fields = append(c.Fields, f)
		}
	}
}

func loadedFieldValue(p PersistentProfile, field string) (any, bool) {
	switch field {
	case "device":
		if p.Binding == "declared" {
			return p.Device, true
		}
	case "mtu":
		if p.MTU != nil && p.FieldStates[field] == "configured" {
			return *p.MTU, true
		}
	case "ipv4_method", "ipv6_method":
		method := p.Methods[strings.TrimSuffix(field, "_method")]
		if method != "" && method != "unknown" && method != "unspecified" {
			return method, true
		}
	case "addresses", "dns", "search":
		if p.FieldStates[field] == "configured" {
			values := map[string][]string{"addresses": p.Addresses, "dns": p.DNS, "search": p.Search}[field]
			return stringSet(values), true
		}
	}
	return nil, false
}

func parseLoadedSettings(raw []byte, requested map[string]bool) (map[string]PersistentProfile, error) {
	result := map[string]PersistentProfile{}
	var fields map[string]string
	allowed := map[string]bool{}
	for _, name := range strings.Split(loadedFields, ",") {
		allowed[name] = true
	}
	flush := func() error {
		if fields == nil {
			return nil
		}
		uuid := strings.ToLower(fields["connection.uuid"])
		if !profileUUID.MatchString(uuid) || !requested[uuid] || len(fields) != len(allowed) || len(result) >= 64 {
			return errNativeSchema
		}
		if _, exists := result[uuid]; exists {
			return errNativeSchema
		}
		if kind := fields["connection.type"]; kind != "802-3-ethernet" && kind != "ethernet" {
			return errNativeSchema
		}
		profile := newPersistentProfile("nm:"+uuid, nil)
		if name := fields["connection.interface-name"]; deviceName.MatchString(name) {
			profile.Device, profile.Binding = name, "declared"
		} else if name != "" && name != "--" {
			return errNativeSchema
		}
		mtu := fields["802-3-ethernet.mtu"]
		if mtu == "auto" || mtu == "0" {
			n := 0 // NM profile's automatic MTU, not a measured kernel MTU.
			profile.MTU, profile.FieldStates["mtu"] = &n, "configured"
		} else {
			persistentMTU(&profile, mtu)
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			profile.Methods[family] = safeMethod(fields[family+".method"])
		}
		for field, suffix := range map[string]string{"addresses": "addresses", "dns": "dns", "search": "dns-search"} {
			values := []string{}
			for _, family := range []string{"ipv4", "ipv6"} {
				value := fields[family+"."+suffix]
				if value == "" || value == "--" {
					continue
				}
				for _, item := range strings.Split(value, ",") {
					values = append(values, strings.TrimSpace(item))
				}
			}
			persistentValues(&profile, field, values)
		}
		result[uuid] = profile
		return nil
	}
	if len(raw) > 1024*1024 || len(requested) > 64 {
		return nil, errNativeSchema
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || !allowed[key] || len(line) > 65536 {
			return nil, errNativeSchema
		}
		if key == "connection.uuid" {
			if err := flush(); err != nil {
				return nil, err
			}
			fields = map[string]string{}
		}
		if fields == nil {
			return nil, errNativeSchema
		}
		if _, exists := fields[key]; exists {
			return nil, errNativeSchema
		}
		value, err := nmUnescape(strings.TrimSpace(value))
		if err != nil || strings.ContainsAny(value, "\x00\r") {
			return nil, errNativeSchema
		}
		fields[key] = value
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return result, nil
}
