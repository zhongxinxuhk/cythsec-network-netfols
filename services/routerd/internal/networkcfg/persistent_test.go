package networkcfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func inspectionReader(t *testing.T) *PersistentReader {
	t.Helper()
	p := NewPersistentReader()
	p.root = t.TempDir()
	p.platform = "linux"
	p.find = func(tool string) (string, error) { return "/usr/bin/" + tool, nil }
	p.run = func(_ context.Context, path string, args []string, _, _ string) ([]byte, error) {
		if filepath.Base(path) == "systemctl" && reflect.DeepEqual(args, []string{"--no-pager", "is-active", "NetworkManager"}) {
			return nil, os.ErrNotExist
		}
		t.Fatal("unexpected native query")
		return nil, errNativeSchema
	}
	return p
}
func writeInspectionFile(t *testing.T, p *PersistentReader, path, content string) {
	t.Helper()
	file := filepath.Join(p.root, strings.TrimPrefix(path, "/"))
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPersistentKeyfileRoundTripAndOpaqueVersions(t *testing.T) {
	p := inspectionReader(t)
	c := fixture()
	c.Backend = "networkmanager"
	preview, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	file := "/etc/NetworkManager/system-connections/" + preview.Artifacts[0].Name
	raw := preview.Artifacts[0].Content + "\n[802-1x]\npassword=fixture-credential-do-not-return\n"
	writeInspectionFile(t, p, file, raw)
	r, err := p.Inspect(context.Background(), c.Backend)
	if err != nil || len(r.Profiles) != 1 || len(r.Sources) != 1 || r.CanApply || r.Status != "partial" {
		t.Fatal(r, err)
	}
	profile := r.Profiles[0]
	if profile.Device != c.Interfaces[0].Device || !profile.OriginVerified || profile.MTU == nil || *profile.MTU != c.Interfaces[0].MTU || !reflect.DeepEqual(profile.Addresses, c.Interfaces[0].Addresses) || profile.FieldStates["dns"] != "configured" {
		t.Fatal(profile)
	}
	encoded, _ := json.Marshal(r)
	if bytes.Contains(encoded, []byte("fixture-credential")) || bytes.Contains(encoded, []byte("password")) {
		t.Fatal("credential in projection")
	}
	if r.Sources[0].VersionTag == hashBytes([]byte(raw)) {
		t.Fatal("raw credential-bearing file digest exposed")
	}
	again, _ := p.Inspect(context.Background(), c.Backend)
	if again.Sources[0].VersionTag != r.Sources[0].VersionTag {
		t.Fatal("unchanged source version drifted")
	}
	writeInspectionFile(t, p, file, raw+"\n# changed\n")
	changed, _ := p.Inspect(context.Background(), c.Backend)
	if changed.Sources[0].VersionTag == r.Sources[0].VersionTag {
		t.Fatal("changed bytes not detected")
	}
	other := NewPersistentReader()
	other.root, other.platform = p.root, "linux"
	next, _ := other.Inspect(context.Background(), c.Backend)
	if next.Sources[0].VersionTag == changed.Sources[0].VersionTag {
		t.Fatal("version identity correlates across service restarts")
	}
}
func TestPersistentFileFailuresDoNotBecomeEmptySuccess(t *testing.T) {
	p := inspectionReader(t)
	base := "/etc/NetworkManager/system-connections/"
	writeInspectionFile(t, p, base+"valid.nmconnection", "[connection]\ntype=ethernet\ninterface-name=eth0\n[ipv4]\nmethod=auto\n")
	writeInspectionFile(t, p, base+"large.nmconnection", strings.Repeat("x", 1024*1024+1))
	if err := os.Symlink(filepath.Join(p.root, base, "valid.nmconnection"), filepath.Join(p.root, base, "symlink.nmconnection")); err != nil {
		t.Fatal(err)
	}
	r, err := p.Inspect(context.Background(), "networkmanager")
	if err != nil || r.Status != "partial" || len(r.Profiles) != 1 || len(r.Sources) != 3 {
		t.Fatal(r, err)
	}
	for _, s := range r.Sources {
		if strings.Contains(s.Path, "symlink") || strings.Contains(s.Path, "large") {
			if s.State != "unavailable" || s.VersionTag != "" || s.Bytes != 0 {
				t.Fatal("unread file given known bytes", s)
			}
		}
	}
	if r.Profiles[0].MTU != nil || r.Profiles[0].FieldStates["mtu"] != "unset" || r.Profiles[0].DNS != nil {
		t.Fatal("missing values converted to defaults")
	}
	if _, err := p.Inspect(context.Background(), "../../etc"); err == nil {
		t.Fatal("arbitrary backend accepted")
	}
}
func TestPersistentNetplanCopiesAllLayersAndKeepsOriginUnverified(t *testing.T) {
	p := inspectionReader(t)
	writeInspectionFile(t, p, "/lib/netplan/10-net.yaml", "vendor-content")
	writeInspectionFile(t, p, "/etc/netplan/10-net.yaml", "persistent-content")
	writeInspectionFile(t, p, "/run/netplan/20-net.yaml", "runtime-content")
	dir := ""
	calls := 0
	p.run = func(_ context.Context, path string, args []string, input, workspace string) ([]byte, error) {
		dir = workspace
		calls++
		if filepath.Base(path) == "netplan" {
			if !reflect.DeepEqual(args, []string{"get", "--root-dir", workspace, "network.ethernets"}) {
				t.Fatal(args)
			}
			for _, source := range []string{"lib/netplan/10-net.yaml", "etc/netplan/10-net.yaml", "run/netplan/20-net.yaml"} {
				if st, e := os.Stat(filepath.Join(workspace, source)); e != nil || st.Mode().Perm() != 0600 {
					t.Fatal("private snapshot missing", e)
				}
			}
			return []byte("netplan YAML"), nil
		}
		if reflect.DeepEqual(args, []string{"-I", "-c", netplanProjection, "--source-trace", workspace}) {
			// Source trace is an independent extension; failure must preserve merged profiles.
			return nil, os.ErrPermission
		}
		if filepath.Base(path) != "python3" || len(args) != 3 || args[0] != "-I" || args[1] != "-c" || args[2] != netplanProjection || input != "netplan YAML" {
			t.Fatal("unregistered projection command")
		}
		return []byte(`{"eth0":{"addresses":["192.0.2.10/24"],"dhcp4":false,"nameservers":{"addresses":[]},"routes":[{"to":"default","via":"192.0.2.1"}]},"uplink":{"match_supported":false}}`), nil
	}
	r, err := p.Inspect(context.Background(), "netplan")
	if err != nil || calls != 3 || r.Status != "observed" || len(r.Profiles) != 2 || len(r.Sources) != 3 || r.NetplanIndex == nil || r.NetplanIndex.State != "unavailable" {
		t.Fatal(r, err)
	}
	if r.Profiles[0].OriginVerified || len(r.Profiles[0].SourceIDs) != 3 || r.Profiles[0].Routes[0].Metric != nil || r.Profiles[1].Binding != "unresolved" || r.Profiles[0].DNS == nil {
		t.Fatal("merged/default fields misattributed", r.Profiles)
	}
	if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private snapshot retained", err)
	}
}
func TestPersistentUCIUsesCommittedCopyAndDiscardsSecrets(t *testing.T) {
	p := inspectionReader(t)
	writeInspectionFile(t, p, "/etc/config/network", "committed-source")
	// Real uci export quotes embedded apostrophes as '\''; multiline credentials
	// also remain one token and never become configuration directives.
	p.run = func(_ context.Context, path string, args []string, input, dir string) ([]byte, error) {
		if filepath.Base(path) != "uci" || !reflect.DeepEqual(args, []string{"-s", "export", filepath.Join(dir, "network")}) || input != "" {
			t.Fatal(args)
		}
		raw, e := os.ReadFile(args[2])
		if e != nil || string(raw) != "committed-source" {
			t.Fatal("wrong snapshot", e)
		}
		return []byte("package network\nconfig interface 'lan'\n option device 'eth0'\n option proto 'static'\n option ipaddr '192.0.2.10'\n option netmask '255.255.255.0'\n list dns '192.0.2.53'\n option password 'do-not-return'\\''secret\nconfig interface fake'\nconfig route 'default_lan'\n option interface 'lan'\n option target '0.0.0.0/0'\n option gateway '192.0.2.1'\n"), nil
	}
	r, err := p.Inspect(context.Background(), "openwrt")
	if err != nil || r.Status != "observed" || len(r.Profiles) != 1 || !r.Profiles[0].OriginVerified || r.Profiles[0].Addresses[0] != "192.0.2.10/24" || r.Profiles[0].Routes[0].Metric != nil {
		t.Fatal(r, err)
	}
	raw, _ := json.Marshal(r)
	if bytes.Contains(raw, []byte("do-not-return")) || bytes.Contains(raw, []byte("fake")) {
		t.Fatal("credential interpreted or returned")
	}
}
func TestPersistentUnavailableAndBusyAreExplicit(t *testing.T) {
	p := inspectionReader(t)
	p.platform = "darwin"
	r, err := p.Inspect(context.Background(), "netplan")
	if err != nil || r.Status != "unsupported" || len(r.Sources) != 0 || len(r.Profiles) != 0 || r.CanApply {
		t.Fatal(r, err)
	}
	p.platform = "linux"
	writeInspectionFile(t, p, "/etc/config/network", "raw")
	entered, release := make(chan struct{}), make(chan struct{})
	p.find = func(string) (string, error) { close(entered); <-release; return "", os.ErrNotExist }
	done := make(chan struct{})
	go func() { defer close(done); r, _ = p.Inspect(context.Background(), "openwrt") }()
	<-entered
	if _, err = p.Inspect(context.Background(), "openwrt"); !errors.Is(err, ErrObservationBusy) {
		t.Fatal("parallel source read accepted", err)
	}
	close(release)
	<-done
	if r.Status != "unavailable" || len(r.Profiles) != 0 || len(r.Sources) != 1 || r.Sources[0].State != "read" {
		t.Fatal("native failure became empty success", r)
	}
}
func TestNetplanPureProjectionDoesNotRequirePythonYAMLForUnitCoverage(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python3 required for projection test", err)
	}
	driver := "import json,sys\nns={'__name__':'projection_test'}\nexec(" + strconv.Quote(netplanProjection) + ",ns)\nprint(json.dumps(ns['project'](json.load(sys.stdin))))\n"
	cmd := exec.Command(python, "-I", "-c", driver)
	cmd.Stdin = strings.NewReader(`{"eth0":{"addresses":["192.0.2.10/24"],"auth":{"password":"private-value"},"match":{"macaddress":"00:11:22:33:44:55"},"routes":[{"to":"default","via":"192.0.2.1","table":100,"password":"private-value"}]}}`)
	raw, err := cmd.Output()
	if err != nil || bytes.Contains(raw, []byte("private-value")) || bytes.Contains(raw, []byte("00:11")) {
		t.Fatal("projection leaked excluded data", string(raw), err)
	}
	profiles, err := parseNetplanProjection(raw, []ConfigSource{{ID: strings.Repeat("a", 64)}})
	if err != nil || len(profiles) != 1 || profiles[0].Binding != "unresolved" || profiles[0].FieldStates["routes"] != "unsupported" {
		t.Fatal(profiles, err)
	}
}

func TestIncompleteNetplanLayerIsNotSilentlyOmitted(t *testing.T) {
	p := inspectionReader(t)
	writeInspectionFile(t, p, "/etc/netplan/10.yaml", "network: {}")
	link := filepath.Join(p.root, "etc/netplan/20.yaml")
	if err := os.Symlink("/absent-source", link); err != nil {
		t.Fatal(err)
	}
	r, err := p.Inspect(context.Background(), "netplan")
	if err != nil || r.Status != "unavailable" || len(r.Sources) != 2 || len(r.Profiles) != 0 {
		t.Fatal("incomplete merged view published", r, err)
	}
}
func TestPersistentComplexFormatsRemainUnknown(t *testing.T) {
	source := strings.Repeat("a", 64)
	p, err := parseKeyfile([]byte("[connection]\ntype=ethernet\ninterface-name=eth0\n[ipv4]\nmethod=manual\naddress1=192.0.2.10/24\nroute1=0.0.0.0/0,192.0.2.1\nroute1_options=table=100\ndns-search=~corp.example\n"), source)
	if err != nil || p.Routes != nil || p.FieldStates["routes"] != "unsupported" || p.Search != nil || p.FieldStates["search"] != "unsupported" {
		t.Fatal(p, err)
	}
	profiles, err := parseNetplanProjection([]byte(`{"eth0":{"gateway4":"192.0.2.1","routes":[{"to":"198.51.100.0/24","via":"192.0.2.2","metric":0}]}}`), []ConfigSource{{ID: source}})
	if err != nil || len(profiles[0].Routes) != 2 || profiles[0].Routes[0].Metric != nil || profiles[0].Routes[1].Metric == nil || *profiles[0].Routes[1].Metric != 0 {
		t.Fatal("default and explicit zero merged", profiles, err)
	}
}

func TestKeyfileGatewayPriorityAndUnsupportedPolicies(t *testing.T) {
	source := strings.Repeat("a", 64)
	raw := "[connection]\ntype=ethernet\ninterface-name=eth0\n[ipv4]\naddress1=192.0.2.10/24;192.0.2.2\ngateway=192.0.2.1\n"
	p, err := parseKeyfile([]byte(raw), source)
	if err != nil || p.FieldStates["addresses"] != "configured" || len(p.Routes) != 1 || p.Routes[0].Gateway != "192.0.2.1" {
		t.Fatal("explicit gateway precedence lost", p, err)
	}
	p, err = parseKeyfile([]byte(raw+"routing-rule1=priority 10 table 100\n"), source)
	if err != nil || p.FieldStates["routes"] != "unsupported" || p.Routes != nil {
		t.Fatal("policy routing silently flattened", p, err)
	}
	profiles, err := parseNetplanProjection([]byte(`{"eth0":{"routing_policy_present":true,"routes":[]}}`), []ConfigSource{{ID: source}})
	if err != nil || profiles[0].FieldStates["routes"] != "unsupported" || profiles[0].Routes != nil {
		t.Fatal(profiles, err)
	}
}

func TestEmptyNativeExportIsUnavailable(t *testing.T) {
	p := inspectionReader(t)
	writeInspectionFile(t, p, "/etc/config/network", "committed-source")
	p.run = func(context.Context, string, []string, string, string) ([]byte, error) { return []byte("\n"), nil }
	r, err := p.Inspect(context.Background(), "openwrt")
	if err != nil || r.Status != "unavailable" || len(r.Profiles) != 0 {
		t.Fatal("empty native output became zero-profile success", r, err)
	}
}
