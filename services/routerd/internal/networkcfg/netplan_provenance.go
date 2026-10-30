package networkcfg

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

type NetplanSourceIndex struct {
	State      string    `json:"state"`
	Scope      string    `json:"scope"`
	ObservedAt time.Time `json:"observed_at"`
	Diagnostic string    `json:"diagnostic"`
	Active     []string  `json:"active_source_ids"`
	Shadowed   []string  `json:"shadowed_source_ids"`
}
type NetplanFieldOrigin struct {
	Field     string   `json:"field"`
	State     string   `json:"state"`
	SourceIDs []string `json:"source_ids"`
	Reason    string   `json:"reason"`
}
type NetplanProfileOrigin struct {
	Scope  string               `json:"scope"`
	Fields []NetplanFieldOrigin `json:"fields"`
}

var netplanTraceFields = []string{"mtu", "dhcp4", "dhcp6", "accept-ra", "addresses", "nameservers.addresses", "nameservers.search", "routes", "gateway4", "gateway6"}

func (p *PersistentReader) traceNetplanSources(ctx context.Context, dir string, merged []byte, r *PersistentInspection) {
	e := &NetplanSourceIndex{State: "unavailable", Scope: "netplan_projected_field_sources", ObservedAt: time.Now().UTC(), Diagnostic: "source_trace_unavailable", Active: []string{}, Shadowed: []string{}}
	r.NetplanIndex = e
	request := struct {
		Sources []map[string]string `json:"sources"`
		Merged  json.RawMessage     `json:"merged"`
	}{Sources: []map[string]string{}, Merged: merged}
	for _, source := range r.Sources {
		request.Sources = append(request.Sources, map[string]string{"id": source.ID, "path": source.Path})
	}
	input, err := json.Marshal(request)
	if err != nil {
		return
	}
	raw, err := p.execute(ctx, "python3", []string{"-I", "-c", netplanProjection, "--source-trace", dir}, string(input), dir)
	if err != nil {
		return
	}
	if err = applyNetplanTrace(raw, merged, r); err != nil {
		e.Diagnostic = "source_trace_schema_unsupported"
	}
}

func netplanSourceOrder(sources []ConfigSource) ([]string, []string, error) {
	priorities := map[string]int{"/lib/netplan": 0, "/etc/netplan": 1, "/run/netplan": 2}
	chosen := map[string]ConfigSource{}
	seen := map[string]bool{}
	paths := map[string]bool{}
	for _, source := range sources {
		rank, ok := priorities[filepath.Dir(source.Path)]
		if !ok || source.State != "read" || seen[source.ID] || paths[source.Path] || source.Path != filepath.Clean(source.Path) || !strings.HasSuffix(source.Path, ".yaml") {
			return nil, nil, errNativeSchema
		}
		seen[source.ID] = true
		paths[source.Path] = true
		name := filepath.Base(source.Path)
		if old, exists := chosen[name]; !exists || rank > priorities[filepath.Dir(old.Path)] {
			chosen[name] = source
		}
	}
	names := make([]string, 0, len(chosen))
	for name := range chosen {
		names = append(names, name)
	}
	sort.Strings(names)
	active := []string{}
	for _, name := range names {
		id := chosen[name].ID
		active = append(active, id)
		delete(seen, id)
	}
	shadowed := []string{}
	for id := range seen {
		shadowed = append(shadowed, id)
	}
	sort.Strings(shadowed)
	return active, shadowed, nil
}

func applyNetplanTrace(raw, merged []byte, r *PersistentInspection) error {
	if r.NetplanIndex == nil {
		return errNativeSchema
	}
	var trace struct {
		Active   []string                        `json:"active_source_ids"`
		Shadowed []string                        `json:"shadowed_source_ids"`
		Profiles map[string][]NetplanFieldOrigin `json:"profiles"`
	}
	var entries map[string]map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1024*1024 || d.Decode(&trace) != nil || d.Decode(new(any)) != io.EOF || json.Unmarshal(merged, &entries) != nil || trace.Active == nil || trace.Shadowed == nil || trace.Profiles == nil || len(trace.Profiles) != len(r.Profiles) {
		return errNativeSchema
	}
	active, shadowed, err := netplanSourceOrder(r.Sources)
	if err != nil || !slices.Equal(active, trace.Active) || !slices.Equal(shadowed, trace.Shadowed) {
		return errNativeSchema
	}
	order := map[string]int{}
	for i, id := range active {
		order[id] = i
	}
	origins := make([]*NetplanProfileOrigin, len(r.Profiles))
	for i, profile := range r.Profiles {
		name, ok := strings.CutPrefix(profile.Reference, "netplan:")
		fields, found := trace.Profiles[name]
		entry, exists := entries[name]
		if !ok || !found || !exists || fields == nil {
			return errNativeSchema
		}
		expected := []string{}
		for _, field := range netplanTraceFields {
			parts := strings.Split(field, ".")
			_, present := entry[parts[0]]
			if present && len(parts) == 2 {
				var nested map[string]json.RawMessage
				if json.Unmarshal(entry[parts[0]], &nested) != nil {
					return errNativeSchema
				}
				_, present = nested[parts[1]]
			}
			if present {
				expected = append(expected, field)
			}
		}
		if len(fields) != len(expected) {
			return errNativeSchema
		}
		for j, field := range fields {
			if field.Field != expected[j] || field.SourceIDs == nil || len(field.SourceIDs) > 64 || (field.State != "traced" && field.State != "unverified") || (field.State == "traced" && (field.Reason != "projection_matches" || len(field.SourceIDs) == 0)) || (field.State == "unverified" && field.Reason != "projection_not_reconciled") {
				return errNativeSchema
			}
			last := -1
			for _, id := range field.SourceIDs {
				n, valid := order[id]
				if !valid || n <= last {
					return errNativeSchema
				}
				last = n
			}
			sequence := field.Field == "addresses" || field.Field == "nameservers.addresses" || field.Field == "nameservers.search" || field.Field == "routes"
			if !sequence && len(field.SourceIDs) > 1 {
				return errNativeSchema
			}
		}
		origins[i] = &NetplanProfileOrigin{Scope: "netplan_projected_field_sources", Fields: fields}
	}
	for i := range r.Profiles {
		r.Profiles[i].FieldOrigins = origins[i]
	}
	r.NetplanIndex.State, r.NetplanIndex.Diagnostic = "indexed", "projection_sources_only"
	r.NetplanIndex.ObservedAt = time.Now().UTC()
	r.NetplanIndex.Active, r.NetplanIndex.Shadowed = active, shadowed
	return nil
}
