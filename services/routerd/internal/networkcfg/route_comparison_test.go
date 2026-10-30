package networkcfg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func routingFixture(uuid string) string {
	return "connection.uuid:" + uuid + "\nconnection.type:802-3-ethernet\nipv4.gateway:192.0.2.1\nipv4.routes:198.51.100.0/24 192.0.2.2 0\nipv4.route-metric:-1\nipv4.route-table:0\nipv4.never-default:no\nipv4.ignore-auto-routes:no\nipv4.routing-rules:\nipv6.gateway:\nipv6.routes:\nipv6.route-metric:-1\nipv6.route-table:0\nipv6.never-default:no\nipv6.ignore-auto-routes:no\nipv6.routing-rules:\n"
}

func TestRoutingComparisonPreservesMetricAndDuplicateEvidence(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	for _, tc := range []struct{ name, from, to, want string }{
		{"same tuple multiset", "not-present", "", "same"},
		{"zero differs from default", "192.0.2.2 0", "192.0.2.2", "different"},
		{"duplicate retained", "192.0.2.2 0", "192.0.2.2 0, 198.51.100.0/24 192.0.2.2 0", "different"},
		{"gateway changed", "gateway:192.0.2.1", "gateway:192.0.2.3", "different"},
		{"route table not flattened", "ipv4.route-table:0", "ipv4.route-table:254", "unknown"},
		{"global metric not flattened", "ipv4.route-metric:-1", "ipv4.route-metric:0", "unknown"},
		{"never default", "ipv4.never-default:no", "ipv4.never-default:yes", "unknown"},
		{"ignore automatic routes", "ipv4.ignore-auto-routes:no", "ipv4.ignore-auto-routes:yes", "unknown"},
		{"rule", "ipv4.routing-rules:", "ipv4.routing-rules:priority 10 from all table 100", "unknown"},
		{"attribute", "192.0.2.2 0", "192.0.2.2 0 onlink=true", "unknown"},
		{"on-link route", "198.51.100.0/24 192.0.2.2 0", "198.51.100.0/24", "unknown"},
		{"wrong family", "ipv6.routes:", "ipv6.routes:198.51.100.0/24 192.0.2.2 0", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inspectionReader(t)
			profile, err := parseKeyfile([]byte("[connection]\ntype=ethernet\nuuid="+uuid+"\ninterface-name=eth0\n[ipv4]\ngateway=192.0.2.1\nroute1=198.51.100.0/24,192.0.2.2,0\n"), strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			profile.LoadReference = "matched"
			r := PersistentInspection{Platform: "linux", Backend: "networkmanager", Profiles: []PersistentProfile{profile}}
			p.run = func(_ context.Context, tool string, args []string, input, dir string) ([]byte, error) {
				if filepath.Base(tool) != "nmcli" || input != "" || dir != "" || !reflect.DeepEqual(args, []string{"-t", "-m", "multiline", "-f", routingFields, "connection", "show", "uuid", uuid}) {
					t.Fatal("unsafe query", tool, args)
				}
				return []byte(strings.Replace(routingFixture(uuid), tc.from, tc.to, 1)), nil
			}
			p.compareRouting(context.Background(), &r)
			c := r.Profiles[0].Routing
			if c.State != tc.want || len(c.Source) != 2 || (tc.want == "unknown" && c.Loaded != nil) {
				t.Fatal(c)
			}
			r.Authority = assessAuthority(r)
			raw, _ := json.Marshal(r)
			if r.Authority.CanAdopt || r.CanApply || (tc.want == "different") != strings.Contains(string(raw), "loaded_routes_different") {
				t.Fatal(r.Authority)
			}
		})
	}
}

func TestSourceRouteControlsCannotBecomeBaselineTuples(t *testing.T) {
	for _, entry := range []string{"route-metric=0", "route-metric=20", "route-table=254", "never-default=true", "ignore-auto-routes=true", "routing-rule1=priority 10 from all table 100", "route1_options=onlink=true"} {
		p, err := parseKeyfile([]byte("[connection]\ntype=ethernet\n[ipv4]\nroute1=198.51.100.0/24,192.0.2.1,0\n"+entry+"\n"), strings.Repeat("a", 64))
		if err != nil || p.FieldStates["routes"] != "unsupported" || p.Routes != nil {
			t.Fatal(entry, p, err)
		}
	}
	p, err := parseKeyfile([]byte("[connection]\ntype=ethernet\n[ipv6]\nroute1=198.51.100.0/24,192.0.2.1,0\n"), strings.Repeat("a", 64))
	if err != nil || p.FieldStates["routes"] != "unsupported" {
		t.Fatal("cross-family source accepted", p, err)
	}
}

func TestRoutingReadFailureDoesNotEraseBasicSettings(t *testing.T) {
	p := inspectionReader(t)
	profile := newPersistentProfile("nm:12345678-1234-1234-1234-123456789abc", nil)
	profile.LoadReference, profile.Loaded = "matched", &LoadedComparison{State: "partial"}
	for _, tc := range []struct {
		raw   string
		err   error
		state string
	}{{"", os.ErrPermission, "unavailable"}, {"connection.uuid:broken\n", nil, "unavailable"}, {"", nil, "unavailable"}} {
		r := PersistentInspection{Backend: "networkmanager", Profiles: []PersistentProfile{profile}}
		p.run = func(context.Context, string, []string, string, string) ([]byte, error) { return []byte(tc.raw), tc.err }
		p.compareRouting(context.Background(), &r)
		if r.Profiles[0].Routing.State != tc.state || r.Profiles[0].Routing.Loaded != nil || r.Profiles[0].Loaded.State != "partial" {
			t.Fatal(r)
		}
	}
}

func TestRoutingLimitsAndUnknownEmptyStayDistinct(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	parse := func(raw string) map[string]string {
		t.Helper()
		r, err := parseNMSettingsBatch([]byte(raw), routingFields, map[string]bool{uuid: true})
		if err != nil {
			t.Fatal(err)
		}
		return r[uuid]
	}
	base := strings.Replace(routingFixture(uuid), "ipv4.gateway:192.0.2.1", "ipv4.gateway:", 1)
	for _, count := range []int{256, 257} {
		routes := strings.TrimSuffix(strings.Repeat("198.51.100.0/24 192.0.2.1 0,", count), ",")
		raw := strings.Replace(base, "198.51.100.0/24 192.0.2.2 0", routes, 1)
		items, err := projectNMRoutes(parse(raw))
		if count == 256 && (err != nil || len(items) != 256) || count == 257 && err == nil {
			t.Fatal(count, len(items), err)
		}
	}
	if _, err := parseNMSettingsBatch([]byte(strings.Replace(base, "ipv4.routes:", "ipv4.routes:"+strings.Repeat("a", 65537), 1)), routingFields, map[string]bool{uuid: true}); err == nil {
		t.Fatal("unbounded line accepted")
	}
	raw := strings.Replace(base, "198.51.100.0/24 192.0.2.2 0", "", 1)
	items, err := projectNMRoutes(parse(raw))
	if err != nil || items == nil || len(items) != 0 {
		t.Fatal("empty routes became unknown", items, err)
	}
	p := inspectionReader(t)
	profile := newPersistentProfile("nm:"+uuid, nil)
	profile.LoadReference = "matched"
	r := PersistentInspection{Backend: "networkmanager", Profiles: []PersistentProfile{profile}}
	p.run = func(context.Context, string, []string, string, string) ([]byte, error) { return []byte(raw), nil }
	p.compareRouting(context.Background(), &r)
	if r.Profiles[0].Routing.State != "unknown" || r.Profiles[0].Routing.Source != nil || r.Profiles[0].Routing.Loaded == nil {
		t.Fatal("unset source became equal to empty", r)
	}
}

func FuzzNMSettingsBatch(f *testing.F) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	for _, seed := range []string{routingFixture(uuid), loadedFixture(uuid), "", "connection.uuid:\x00", "connection.uuid:" + uuid + "\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := parseNMSettingsBatch([]byte(raw), routingFields, map[string]bool{uuid: true})
		if err != nil {
			if r != nil {
				t.Fatal("partial result on error")
			}
			return
		}
		if len(r) > 1 {
			t.Fatal("unrequested profile")
		}
		for id, fields := range r {
			if id != uuid || len(fields) != len(strings.Split(routingFields, ",")) {
				t.Fatal("schema guard bypassed")
			}
			projectNMRoutes(fields)
		}
	})
}
