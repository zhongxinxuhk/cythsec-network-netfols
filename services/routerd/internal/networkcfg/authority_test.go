package networkcfg

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

type safetyInfo struct {
	os.FileInfo
	uid, gid uint32
	mode     os.FileMode
}

func (s safetyInfo) Sys() any          { return &syscall.Stat_t{Uid: s.uid, Gid: s.gid} }
func (s safetyInfo) Mode() os.FileMode { return s.mode }
func TestSourcePermissionBaselineDoesNotRequireChown(t *testing.T) {
	for _, tc := range []struct {
		backend string
		uid     uint32
		mode    os.FileMode
		status  string
	}{
		{"networkmanager", 0, 0600, "meets_baseline"},
		{"networkmanager", 0, 0644, "blocked"},
		{"netplan", 0, 0644, "review"},
		{"openwrt", 0, 0660, "blocked"},
		{"netplan", 1000, 0600, "blocked"},
		{"netplan", 0, 0600 | os.ModeSetuid, "blocked"},
	} {
		s := sourceSafety(safetyInfo{uid: tc.uid, gid: 0, mode: tc.mode}, tc.backend)
		if s.Status != tc.status || s.UID == nil || *s.UID != tc.uid || s.Mode == "" {
			t.Fatal(tc, s)
		}
	}
	if sourceSafety(nil, "netplan").Status != "unknown" {
		t.Fatal("missing file permissions became known")
	}
}
func TestSourceIdentityDetectsMutationAndPathReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, _ := f.Stat()
	after, _ := f.Stat()
	current, _ := os.Lstat(path)
	if !stableSource(before, after, current) {
		t.Fatal("unchanged regular file not stable")
	}
	if err = os.WriteFile(path, []byte("changed-content"), 0600); err != nil {
		t.Fatal(err)
	}
	after, _ = f.Stat()
	current, _ = os.Lstat(path)
	if stableSource(before, after, current) {
		t.Fatal("in-place mutation missed")
	}
	before = after
	other := filepath.Join(dir, "replacement")
	os.WriteFile(other, []byte("changed-content"), 0600)
	os.Rename(other, path)
	current, _ = os.Lstat(path)
	if stableSource(before, after, current) {
		t.Fatal("replaced path matched old descriptor")
	}
	os.Remove(path)
	os.Symlink(other, path)
	current, _ = os.Lstat(path)
	if stableSource(before, after, current) {
		t.Fatal("symbolic link accepted as current source")
	}
}
func TestManagerReferencesAreNotContentOrActivationProof(t *testing.T) {
	p := inspectionReader(t)
	uuid := "12345678-1234-1234-1234-123456789abc"
	path := "/etc/NetworkManager/system-connections/lan.nmconnection"
	writeInspectionFile(t, p, path, "[connection]\ntype=ethernet\nuuid="+uuid+"\ninterface-name=eth0\n[ipv4]\nmethod=manual\naddress1=192.0.2.10/24\n")
	calls := 0
	p.run = func(_ context.Context, tool string, args []string, input, dir string) ([]byte, error) {
		calls++
		if input != "" || dir != "" {
			t.Fatal("metadata query has injected input")
		}
		if filepath.Base(tool) == "systemctl" {
			if !reflect.DeepEqual(args, []string{"--no-pager", "is-active", "NetworkManager"}) {
				t.Fatal(args)
			}
			return []byte("active\n"), nil
		}
		if filepath.Base(tool) != "nmcli" || !reflect.DeepEqual(args, []string{"-t", "-f", "UUID,FILENAME", "connection", "show"}) {
			t.Fatal("write/secret query", tool, args)
		}
		return []byte(uuid + ":" + path + "\n"), nil
	}
	r, err := p.Inspect(context.Background(), "networkmanager")
	if err != nil || calls != 2 || r.Manager == nil || r.Manager.State != "observed" || r.Profiles[0].LoadReference != "matched" || r.Authority == nil || r.Authority.CanAdopt || r.CanApply {
		t.Fatal(r, err)
	}
	if r.Sources[0].Safety == nil || r.Sources[0].Safety.Stable == nil || !*r.Sources[0].Safety.Stable {
		t.Fatal("descriptor metadata missing")
	}
	// Isolate baseline permissions from the test process UID; even all local checks
	// matching never imply runtime-content synchronization or execution permission.
	zero := uint32(0)
	stable := true
	r.Sources[0].Safety = &SourceSafety{UID: &zero, GID: &zero, Mode: "0600", Stable: &stable, Status: "meets_baseline", Codes: []string{}}
	a := assessAuthority(r)
	if a.Status != "blocked" || a.CanAdopt {
		t.Fatal("reference match became execution permit", a)
	}
}
func TestManagerReferenceMismatchAndUnavailableStayExplicit(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	for _, tc := range []struct{ raw, state string }{
		{"", "not_observed"},
		{uuid + ":--\n", "unknown"},
		{uuid + ":/run/NetworkManager/system-connections/other.nmconnection\n", "conflicting"},
		{uuid + ":/etc/NetworkManager/system-connections/lan.nmconnection\n" + uuid + ":/etc/NetworkManager/system-connections/lan.nmconnection\n", "conflicting"},
		{"broken row\n", "unknown"},
	} {
		p := inspectionReader(t)
		writeInspectionFile(t, p, "/etc/NetworkManager/system-connections/lan.nmconnection", "[connection]\ntype=ethernet\nuuid="+uuid+"\n")
		p.run = func(_ context.Context, tool string, _ []string, _, _ string) ([]byte, error) {
			if filepath.Base(tool) == "systemctl" {
				return []byte("active"), nil
			}
			return []byte(tc.raw), nil
		}
		r, err := p.Inspect(context.Background(), "networkmanager")
		if err != nil || r.Profiles[0].LoadReference != tc.state || r.Authority.CanAdopt {
			t.Fatal(tc, r, err)
		}
		if strings.HasPrefix(tc.raw, "broken") && r.Manager.State != "unavailable" {
			t.Fatal("malformed inventory became absence")
		}
	}
	refs, err := parseManagerReferences([]byte(uuid + ":/etc/path\\:with-colon.nmconnection\n"))
	if err != nil || refs[uuid][0] != "/etc/path:with-colon.nmconnection" {
		t.Fatal(refs, err)
	}
}
