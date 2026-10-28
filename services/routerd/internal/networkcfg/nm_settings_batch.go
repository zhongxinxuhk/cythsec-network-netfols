package networkcfg

import (
	"bufio"
	"bytes"
	"strings"
)

// parseNMSettingsBatch is shared by two independent read-only queries. Bounds
// apply before projection; no arbitrary native fields survive this boundary.
func parseNMSettingsBatch(raw []byte, selected string, requested map[string]bool) (map[string]map[string]string, error) {
	if len(raw) > 1024*1024 || len(requested) > 64 {
		return nil, errNativeSchema
	}
	result := map[string]map[string]string{}
	allowed := map[string]bool{}
	for _, name := range strings.Split(selected, ",") {
		allowed[name] = true
	}
	var fields map[string]string
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
		result[uuid] = fields
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 65537)
	for scanner.Scan() {
		line := scanner.Text()
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
	if scanner.Err() != nil || flush() != nil {
		return nil, errNativeSchema
	}
	return result, nil
}
