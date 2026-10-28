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

func loadedFixture(uuid string) string {
	return "connection.uuid:" + uuid + "\nconnection.type:802-3-ethernet\nconnection.interface-name:eth0\n802-3-ethernet.mtu:1500\nipv4.method:manual\nipv6.method:disabled\nipv4.addresses:192.0.2.10/24\nipv6.addresses:\nipv4.dns:192.0.2.53, 192.0.2.54\nipv6.dns:\nipv4.dns-search:example.test\nipv6.dns-search:\n"
}

func TestLoadedSettingsComparisonIsBoundedWhitelistAndPartial(t *testing.T) {
	const uuid = "12345678-1234-1234-1234-123456789abc"
	const path = "/etc/NetworkManager/system-connections/lan.nmconnection"
	for _, tc := range []struct{ name, from, to, want string }{
		{"same selected fields", "nothing", "", "partial"},
		{"MTU drift", "mtu:1500", "mtu:1400", "different"},
		{"automatic MTU is a profile value", "mtu:1500", "mtu:auto", "different"},
		{"method drift", "ipv4.method:manual", "ipv4.method:auto", "different"},
		{"address drift", "192.0.2.10/24", "192.0.2.11/24", "different"},
		{"DNS drift", "192.0.2.54", "192.0.2.55", "different"},
		{"device drift", "interface-name:eth0", "interface-name:eth1", "different"},
		{"set order not covered", "192.0.2.53, 192.0.2.54", "192.0.2.54, 192.0.2.53", "partial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inspectionReader(t)
			writeInspectionFile(t, p, path, "[connection]\ntype=ethernet\nuuid="+uuid+"\ninterface-name=eth0\n[ethernet]\nmtu=1500\n[ipv4]\nmethod=manual\naddress1=192.0.2.10/24\ndns=192.0.2.53;192.0.2.54;\ndns-search=example.test;\n[ipv6]\nmethod=disabled\n[802-1x]\npassword=fixture-private-excluded\n")
			settingsCalls := 0
			p.run = func(_ context.Context, tool string, args []string, input, dir string) ([]byte, error) {
				if input != "" || dir != "" {
					t.Fatal("input injected into metadata query")
				}
				if filepath.Base(tool) == "systemctl" {
					return []byte("active"), nil
				}
				if reflect.DeepEqual(args, []string{"-t", "-f", "UUID,FILENAME", "connection", "show"}) {
					return []byte(uuid + ":" + path + "\n"), nil
				}
				if reflect.DeepEqual(args, []string{"-t", "-m", "multiline", "-f", "GENERAL.DEVICE,GENERAL.STATE,GENERAL.CON-UUID", "device", "show"}) {
					return nil, os.ErrPermission
				}
				if reflect.DeepEqual(args, []string{"-t", "-m", "multiline", "-f", routingFields, "connection", "show", "uuid", uuid}) {
					return nil, os.ErrPermission
				}
				if filepath.Base(tool) != "nmcli" || !reflect.DeepEqual(args, []string{"-t", "-m", "multiline", "-f", loadedFields, "connection", "show", "uuid", uuid}) {
					t.Fatal("unexpected or broad query", tool, args)
				}
				settingsCalls++
				return []byte(strings.Replace(loadedFixture(uuid), tc.from, tc.to, 1)), nil
			}
			r, err := p.Inspect(context.Background(), "networkmanager")
			if err != nil || settingsCalls != 1 || r.Profiles[0].Loaded.State != tc.want || len(r.Profiles[0].Loaded.Fields) != 7 || r.CanApply || r.Authority.CanAdopt {
				t.Fatal(r, err)
			}
			for _, f := range r.Profiles[0].Loaded.Fields {
				if f.State == "unknown" || f.Source == nil || f.Loaded == nil {
					t.Fatal("explicit fields not compared", f)
				}
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "fixture-private") || strings.Contains(string(raw), "password") {
				t.Fatal("credential-bearing source leaked")
			}
			if (tc.want == "different") != strings.Contains(string(raw), "loaded_settings_different") {
				t.Fatal("drift not reflected in authority")
			}
		})
	}
}

func TestLoadedSettingsSchemaAndUnavailableNeverBecomeMatch(t *testing.T) {
	const uuid = "12345678-1234-1234-1234-123456789abc"
	base := loadedFixture(uuid)
	for _, raw := range []string{
		base + base, base + "802-1x.password:fixture-private\n",
		strings.Replace(base, "ipv6.method:disabled\n", "", 1),
		strings.Replace(base, "connection.type:802-3-ethernet", "connection.type:vpn", 1),
		strings.Replace(base, uuid, "87654321-1234-1234-1234-123456789abc", 1),
		strings.Replace(base, "interface-name:eth0", "interface-name:bad\\x", 1),
		strings.Repeat("a", 1024*1024+1),
	} {
		if _, err := parseLoadedSettings([]byte(raw), map[string]bool{uuid: true}); err == nil {
			t.Fatal("unsafe/incomplete batch accepted")
		}
	}
	for _, raw := range []string{"", base} {
		p := inspectionReader(t)
		profile := newPersistentProfile("nm:"+uuid, nil)
		profile.LoadReference = "matched"
		r := PersistentInspection{Backend: "networkmanager", Profiles: []PersistentProfile{profile}}
		p.run = func(context.Context, string, []string, string, string) ([]byte, error) { return []byte(raw), nil }
		p.compareLoadedSettings(context.Background(), &r)
		c := r.Profiles[0].Loaded
		if raw == "" && (c.State != "unavailable" || len(c.Fields) != 0) {
			t.Fatal("empty successful output became match", c)
		}
		if raw != "" {
			for _, f := range c.Fields {
				if f.State != "unknown" || f.Source != nil {
					t.Fatal("unset source became equal to daemon defaults", f)
				}
			}
		}
	}
}

func TestLoadedSettingsBatchCorrelatesUUIDsAndSkipsUnmatchedReferences(t *testing.T) {
	uuid1, uuid2 := "12345678-1234-1234-1234-123456789abc", "87654321-1234-1234-1234-123456789abc"
	p := inspectionReader(t)
	r := PersistentInspection{Backend: "networkmanager", Profiles: []PersistentProfile{
		{Reference: "nm:" + uuid1, LoadReference: "matched"}, {Reference: "nm:" + uuid2, LoadReference: "matched"}, {Reference: "file:opaque", LoadReference: "unknown"},
	}}
	mtu1, mtu2 := 1500, 1400
	r.Profiles[0].MTU, r.Profiles[0].FieldStates = &mtu1, map[string]string{"mtu": "configured"}
	r.Profiles[1].MTU, r.Profiles[1].FieldStates = &mtu2, map[string]string{"mtu": "configured"}
	calls := 0
	p.run = func(_ context.Context, _ string, args []string, _, _ string) ([]byte, error) {
		calls++
		if !reflect.DeepEqual(args[7:], []string{"uuid", uuid1, "uuid", uuid2}) {
			t.Fatal(args)
		}
		return []byte(strings.Replace(loadedFixture(uuid2), "mtu:1500", "mtu:1400", 1) + loadedFixture(uuid1)), nil
	}
	p.compareLoadedSettings(context.Background(), &r)
	if calls != 1 || r.Profiles[0].Loaded.State != "partial" || r.Profiles[1].Loaded.State != "partial" || r.Profiles[2].Loaded.State != "not_checked" {
		t.Fatal(r)
	}
	if r.Profiles[0].Loaded.Fields[1].Loaded != 1500 || r.Profiles[1].Loaded.Fields[1].Loaded != 1400 {
		t.Fatal("batch result assigned by output order instead of UUID")
	}
	for _, platform := range []string{"darwin", "linux"} {
		p.platform = platform
		r.Backend = "openwrt"
		p.compareLoadedSettings(context.Background(), &r)
	}
	if calls != 1 {
		t.Fatal("queried unrelated backend or platform")
	}
	p.platform, r.Backend = "linux", "networkmanager"
	p.run = func(context.Context, string, []string, string, string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}
	p.compareLoadedSettings(context.Background(), &r)
	if r.Profiles[0].Loaded.State != "unavailable" || len(r.Profiles[0].Loaded.Fields) != 0 {
		t.Fatal("timeout became successful comparison")
	}
}
