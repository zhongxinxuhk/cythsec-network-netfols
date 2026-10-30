package networkcfg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNMDeviceAssociationsKeepUnknownAndInactiveDistinct(t *testing.T) {
	const uuid = "12345678-1234-1234-1234-123456789abc"
	const other = "87654321-1234-1234-1234-123456789abc"
	for _, tc := range []struct {
		name, device, uuid, want string
		state                    int
	}{
		{"active", "eth0", uuid, "active", 100},
		{"case insensitive", "eth0", strings.ToUpper(uuid), "active", 100},
		{"other profile", "eth0", other, "conflicting", 100},
		{"other preparing", "eth0", other, "conflicting", 40},
		{"no uuid", "eth0", "--", "unknown", 100},
		{"unmanaged", "eth0", "--", "unmanaged", 10},
		{"unavailable", "eth0", "--", "unavailable_device", 20},
		{"disconnected", "eth0", "--", "inactive", 30},
		{"failed", "eth0", "--", "inactive", 120},
		{"preparing", "eth0", uuid, "transitioning", 40},
		{"deactivating", "eth0", uuid, "transitioning", 110},
		{"unknown", "eth0", "--", "unknown", 0},
		{"not visible", "eth1", uuid, "not_observed", 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inspectionReader(t)
			writeInspectionFile(t, p, "/etc/NetworkManager/system-connections/lan.nmconnection", "[connection]\ntype=ethernet\nuuid="+uuid+"\ninterface-name=eth0\n")
			p.run = func(_ context.Context, tool string, args []string, input, dir string) ([]byte, error) {
				if input != "" || dir != "" {
					t.Fatal("metadata probe received input")
				}
				if filepath.Base(tool) == "systemctl" {
					return []byte("active\n"), nil
				}
				if reflect.DeepEqual(args, []string{"-t", "-m", "multiline", "-f", "GENERAL.DEVICE,GENERAL.STATE,GENERAL.CON-UUID", "device", "show"}) {
					return []byte("GENERAL.DEVICE:" + tc.device + "\nGENERAL.STATE:" + strconv.Itoa(tc.state) + " (fixture)\nGENERAL.CON-UUID:" + tc.uuid + "\n"), nil
				}
				// Device evidence must survive an independently unavailable file-reference query.
				return nil, os.ErrPermission
			}
			r, err := p.Inspect(context.Background(), "networkmanager")
			if err != nil || r.Devices.State != "observed" || r.Manager.State != "unavailable" || r.Profiles[0].Association.State != tc.want || r.CanApply || r.Authority.CanAdopt {
				t.Fatal(r, err)
			}
			a := r.Profiles[0].Association
			if tc.want == "active" && (a.Managed == nil || !*a.Managed || a.DeviceState == nil || *a.DeviceState != 100 || a.ActiveProfileMatches == nil || !*a.ActiveProfileMatches) {
				t.Fatal("active lacks positive evidence", a)
			}
			if tc.state == 0 && (a.Managed != nil || a.ActiveProfileMatches != nil) {
				t.Fatal("unknown became false", a)
			}
			raw, _ := json.Marshal(r)
			if tc.uuid == other && strings.Contains(string(raw), other) {
				t.Fatal("unrelated active UUID returned")
			}
			if tc.want != "active" && !strings.Contains(string(raw), "device_association_"+tc.want) {
				t.Fatal("device blocker missing")
			}
		})
	}
}

func TestNMDeviceSchemaFailuresCannotBecomeEmptySuccess(t *testing.T) {
	valid := "GENERAL.DEVICE:eth0\nGENERAL.STATE:30 (disconnected)\nGENERAL.CON-UUID:--\n"
	for _, raw := range []string{
		"GENERAL.STATE:100\n", valid + valid,
		strings.Replace(valid, "30 (disconnected)", "130 (future)", 1),
		strings.Replace(valid, "30 (disconnected)", "31", 1),
		strings.Replace(valid, "GENERAL.CON-UUID:--\n", "", 1),
		valid + "GENERAL.STATE:100\n", valid + "SECRET:private\n",
		strings.Replace(valid, "eth0", "eth\\x", 1),
		strings.Replace(valid, "--", "bad-uuid", 1),
		strings.Repeat("a", 1024*1024+1),
	} {
		if _, err := parseNMDeviceReferences([]byte(raw)); err == nil {
			t.Fatal("invalid inventory accepted")
		}
		p := inspectionReader(t)
		p.run = func(_ context.Context, tool string, _ []string, _, _ string) ([]byte, error) {
			if filepath.Base(tool) == "systemctl" {
				return []byte("active"), nil
			}
			return []byte(raw), nil
		}
		r, err := p.Inspect(context.Background(), "networkmanager")
		if err != nil || r.Devices.State != "unavailable" || r.Devices.Diagnostic != "device_schema_unsupported" {
			t.Fatal(r.Devices, err)
		}
	}
	for _, raw := range []string{valid, ""} {
		if _, err := parseNMDeviceReferences([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	var oversized strings.Builder
	for i := 0; i < 513; i++ {
		oversized.WriteString("GENERAL.DEVICE:eth" + strconv.Itoa(i) + "\nGENERAL.STATE:30\nGENERAL.CON-UUID:--\n")
	}
	if _, err := parseNMDeviceReferences([]byte(oversized.String())); err == nil {
		t.Fatal("device count limit ignored")
	}
}

func TestDeviceEvidenceDoesNotRunOnUnsupportedPlatforms(t *testing.T) {
	p := inspectionReader(t)
	p.platform = "darwin"
	p.run = func(context.Context, string, []string, string, string) ([]byte, error) {
		t.Fatal("host query on unsupported platform")
		return nil, nil
	}
	r, err := p.Inspect(context.Background(), "networkmanager")
	if err != nil || r.Devices.State != "unsupported" {
		t.Fatal(r, err)
	}
}

func TestDeviceNameAloneDoesNotResolveProfileAssociation(t *testing.T) {
	p := inspectionReader(t)
	for _, profile := range []PersistentProfile{
		{Reference: "opaque:file", Device: "eth0", Binding: "declared", Association: &DeviceAssociation{State: "unknown"}},
		{Reference: "nm:12345678-1234-1234-1234-123456789abc", Device: "eth0", Binding: "unresolved", Association: &DeviceAssociation{State: "unknown"}},
	} {
		r := PersistentInspection{Profiles: []PersistentProfile{profile}, Devices: &DeviceEvidence{State: "unavailable"}}
		p.run = func(context.Context, string, []string, string, string) ([]byte, error) {
			return []byte("GENERAL.DEVICE:eth0\nGENERAL.STATE:100\nGENERAL.CON-UUID:12345678-1234-1234-1234-123456789abc\n"), nil
		}
		p.correlateNMDevices(context.Background(), &r)
		if r.Profiles[0].Association.State != "unknown" || r.Profiles[0].Association.Managed != nil {
			t.Fatal("literal name became verified binding")
		}
	}
}
