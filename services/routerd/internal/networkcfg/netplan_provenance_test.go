package networkcfg

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func pureNetplanTrace(t *testing.T, documents []map[string]any, merged map[string]any) []byte {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	driver := "import json,sys\nns={'__name__':'trace_test'}\nexec(" + strconv.Quote(netplanProjection) + ",ns)\nv=json.load(sys.stdin)\nprint(json.dumps(ns['trace_sources'](v['documents'],v['merged'])))"
	input, _ := json.Marshal(map[string]any{"documents": documents, "merged": merged})
	cmd := exec.Command(python, "-I", "-c", driver)
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal("pure source trace failed", err)
	}
	return raw
}

func provenanceFixture(t *testing.T) ([]byte, []byte, PersistentInspection) {
	t.Helper()
	ids := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)}
	paths := []string{"/lib/netplan/10.yaml", "/etc/netplan/10.yaml", "/run/netplan/20.yaml", "/lib/netplan/30.yaml"}
	profiles := []map[string]any{
		{"password": "fixture-private-never-return", "mtu": 9999},
		{"mtu": 1500, "dhcp4": false, "addresses": []string{"192.0.2.10/24"}, "nameservers": map[string]any{"addresses": []string{}}},
		{"mtu": 1400, "addresses": []string{"2001:db8::1/64"}},
		{"mtu": 1280, "nameservers": map[string]any{"search": []string{"example.test"}}},
	}
	documents := []map[string]any{}
	sources := []ConfigSource{}
	for i, id := range ids {
		documents = append(documents, map[string]any{"id": id, "path": paths[i], "document": map[string]any{"network": map[string]any{"ethernets": map[string]any{"lan": profiles[i]}}}})
		sources = append(sources, ConfigSource{ID: id, Path: paths[i], State: "read", Storage: "persistent"})
	}
	merged := map[string]any{"lan": map[string]any{"mtu": 1280, "dhcp4": false, "addresses": []string{"192.0.2.10/24", "2001:db8::1/64"}, "nameservers": map[string]any{"addresses": []string{}, "search": []string{"example.test"}}}}
	raw := pureNetplanTrace(t, documents, merged)
	encoded, _ := json.Marshal(merged)
	parsed, err := parseNetplanProjection(encoded, sources)
	if err != nil {
		t.Fatal(err)
	}
	r := PersistentInspection{Backend: "netplan", Platform: "linux", Status: "observed", Sources: sources, Profiles: parsed, NetplanIndex: &NetplanSourceIndex{State: "unavailable"}}
	return raw, encoded, r
}

func TestNetplanFieldSourcesRespectFileShadowingAndNativeProjection(t *testing.T) {
	raw, merged, r := provenanceFixture(t)
	if bytes.Contains(raw, []byte("fixture-private")) || bytes.Contains(raw, []byte("192.0.2")) || bytes.Contains(raw, []byte("example.test")) {
		t.Fatal("source values or secrets escaped provenance projection")
	}
	if err := applyNetplanTrace(raw, merged, &r); err != nil {
		t.Fatal(err)
	}
	if r.NetplanIndex.State != "indexed" || !reflect.DeepEqual(r.NetplanIndex.Active, []string{strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)}) || !reflect.DeepEqual(r.NetplanIndex.Shadowed, []string{strings.Repeat("a", 64)}) {
		t.Fatal(r.NetplanIndex)
	}
	fields := map[string]NetplanFieldOrigin{}
	for _, field := range r.Profiles[0].FieldOrigins.Fields {
		fields[field.Field] = field
		if field.State != "traced" {
			t.Fatal(field)
		}
	}
	if !reflect.DeepEqual(fields["mtu"].SourceIDs, []string{strings.Repeat("d", 64)}) || !reflect.DeepEqual(fields["addresses"].SourceIDs, []string{strings.Repeat("b", 64), strings.Repeat("c", 64)}) || len(fields["nameservers.addresses"].SourceIDs) != 1 {
		t.Fatal(fields)
	}
	if r.Profiles[0].OriginVerified || r.CanApply || assessAuthority(r).CanAdopt {
		t.Fatal("partial field sources became full provenance or adoption permission")
	}
}

func TestNetplanTraceRejectsFalseSourceMetadataAtomically(t *testing.T) {
	raw, merged, _ := provenanceFixture(t)
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["active_source_ids"] = []string{strings.Repeat("a", 64)} },
		func(v map[string]any) { v["shadowed_source_ids"] = []string{} },
		func(v map[string]any) { v["extra"] = true },
		func(v map[string]any) {
			fields := v["profiles"].(map[string]any)["lan"].([]any)
			fields[0].(map[string]any)["source_ids"] = []string{strings.Repeat("a", 64)}
		},
		func(v map[string]any) {
			fields := v["profiles"].(map[string]any)["lan"].([]any)
			fields[0].(map[string]any)["source_ids"] = []string{strings.Repeat("b", 64), strings.Repeat("d", 64)}
		},
		func(v map[string]any) { v["profiles"].(map[string]any)["lan"] = []any{} },
		func(v map[string]any) {
			fields := v["profiles"].(map[string]any)["lan"].([]any)
			fields[0].(map[string]any)["state"] = "verified_all"
		},
	} {
		var value map[string]any
		json.Unmarshal(raw, &value)
		mutate(value)
		changed, _ := json.Marshal(value)
		_, _, r := provenanceFixture(t)
		if err := applyNetplanTrace(changed, merged, &r); err == nil || r.Profiles[0].FieldOrigins != nil || r.NetplanIndex.State != "unavailable" {
			t.Fatal("unsafe or partial provenance accepted", err, r)
		}
	}
}

func TestNetplanTraceMismatchRemainsBlockedAndTyped(t *testing.T) {
	id := strings.Repeat("a", 64)
	docs := []map[string]any{{"id": id, "path": "/etc/netplan/10.yaml", "document": map[string]any{"network": map[string]any{"ethernets": map[string]any{"lan": map[string]any{"mtu": 1500, "routes": []any{map[string]any{"to": "default", "via": "192.0.2.1", "metric": true}}}}}}}}
	merged := map[string]any{"lan": map[string]any{"mtu": 1400, "routes": []any{map[string]any{"to": "default", "via": "192.0.2.1", "metric": 1, "unsupported_options": false}}}}
	raw := pureNetplanTrace(t, docs, merged)
	var trace struct {
		Profiles map[string][]NetplanFieldOrigin `json:"profiles"`
	}
	if json.Unmarshal(raw, &trace) != nil {
		t.Fatal("invalid result")
	}
	for _, field := range trace.Profiles["lan"] {
		if field.State != "unverified" {
			t.Fatal("mismatch/type coercion became traced", field)
		}
	}
}
