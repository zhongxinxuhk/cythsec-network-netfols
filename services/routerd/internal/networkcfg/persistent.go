package networkcfg

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

//go:embed netplan_projection.py
var netplanProjection string

type ConfiguredRoute struct {
	Destination string  `json:"destination"`
	Gateway     string  `json:"gateway"`
	Metric      *uint32 `json:"metric"`
}
type ConfigSource struct {
	ID         string        `json:"id"`
	Path       string        `json:"path"`
	Storage    string        `json:"storage"`
	VersionTag string        `json:"version_tag"`
	Bytes      int           `json:"bytes"`
	State      string        `json:"state"`
	Safety     *SourceSafety `json:"safety,omitempty"`
}
type PersistentProfile struct {
	Reference      string             `json:"reference"`
	Device         string             `json:"device"`
	Binding        string             `json:"binding"`
	Methods        map[string]string  `json:"methods"`
	MTU            *int               `json:"mtu"`
	Addresses      []string           `json:"addresses"`
	DNS            []string           `json:"dns"`
	Search         []string           `json:"search"`
	Routes         []ConfiguredRoute  `json:"routes"`
	FieldStates    map[string]string  `json:"field_states"`
	SourceIDs      []string           `json:"source_ids"`
	OriginVerified bool               `json:"origin_verified"`
	LoadReference  string             `json:"load_reference,omitempty"`
	Association    *DeviceAssociation `json:"device_association,omitempty"`
	Loaded         *LoadedComparison  `json:"loaded_comparison,omitempty"`
}
type PersistentInspection struct {
	ID         string              `json:"id"`
	Backend    string              `json:"backend"`
	Platform   string              `json:"platform"`
	Scope      string              `json:"scope"`
	ObservedAt time.Time           `json:"observed_at"`
	Status     string              `json:"status"`
	CanApply   bool                `json:"can_apply"`
	Sources    []ConfigSource      `json:"sources"`
	Profiles   []PersistentProfile `json:"profiles"`
	Warnings   []string            `json:"warnings"`
	Manager    *ManagerReferences  `json:"manager,omitempty"`
	Authority  *AuthorityReport    `json:"authority,omitempty"`
	Devices    *DeviceEvidence     `json:"device_evidence,omitempty"`
}
type sourceFile struct {
	meta    ConfigSource
	content []byte
}
type PersistentReader struct {
	platform, root string
	find           func(string) (string, error)
	run            func(context.Context, string, []string, string, string) ([]byte, error)
	gate           chan struct{}
	fingerprintKey []byte
}

func NewPersistentReader() *PersistentReader {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		key = nil
	}
	return &PersistentReader{runtime.GOOS, "/", findNetworkTool, captureProbeCommand, make(chan struct{}, 1), key}
}
func ValidBackend(backend string) bool {
	return backend == "netplan" || backend == "networkmanager" || backend == "openwrt"
}
func newPersistentProfile(ref string, sources []string) PersistentProfile {
	return PersistentProfile{Reference: ref, Binding: "unresolved", Methods: map[string]string{}, FieldStates: map[string]string{"mtu": "unset", "addresses": "unset", "dns": "unset", "search": "unset", "routes": "unset"}, SourceIDs: sources}
}

// Inspect reads source bytes, never daemon-memory settings or staged UCI changes.
func (p *PersistentReader) Inspect(ctx context.Context, backend string) (PersistentInspection, error) {
	if !ValidBackend(backend) {
		return PersistentInspection{}, errors.New("选择受支持的目标管理器")
	}
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	default:
		return PersistentInspection{}, ErrObservationBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	r := PersistentInspection{Backend: backend, Platform: p.platform, Scope: map[string]string{"netplan": "merged_ethernets", "networkmanager": "keyfile_profiles", "openwrt": "committed_network"}[backend], Status: "observed", Sources: []ConfigSource{}, Profiles: []PersistentProfile{}, Warnings: []string{"non_atomic_file_snapshot", "runtime_and_adoption_not_verified"}}
	finish := func() (PersistentInspection, error) {
		p.correlateManager(ctx, &r)
		p.compareLoadedSettings(ctx, &r)
		r.Authority = assessAuthority(r)
		r.Warnings = stringSet(r.Warnings)
		r.ObservedAt = time.Now().UTC()
		raw, _ := json.Marshal(r)
		r.ID = hashBytes(raw)
		return r, nil
	}
	if p.platform != "linux" {
		r.Status = "unsupported"
		r.Warnings = append(r.Warnings, "unsupported_platform")
		return finish()
	}
	if len(p.fingerprintKey) != 32 {
		r.Status = "unavailable"
		r.Warnings = append(r.Warnings, "version_identity_unavailable")
		return finish()
	}
	files, incomplete := p.readSources(ctx, backend)
	for _, file := range files {
		r.Sources = append(r.Sources, file.meta)
	}
	if incomplete {
		r.Status = "partial"
		r.Warnings = append(r.Warnings, "source_read_incomplete")
	}
	if backend == "networkmanager" {
		r.Warnings = append(r.Warnings, "legacy_ifcfg_and_plugins_not_inspected")
		r.Status = "partial"
	}
	if len(files) == 0 {
		if incomplete {
			r.Status = "unavailable"
		}
		r.Warnings = append(r.Warnings, "no_supported_source_files")
		return finish()
	}
	if backend == "networkmanager" {
		refs := map[string]bool{}
		for i, file := range files {
			if file.meta.State != "read" {
				continue
			}
			profile, err := parseKeyfile(file.content, file.meta.ID)
			if err != nil {
				r.Sources[i].State = "unsupported"
				r.Status = "partial"
				r.Warnings = append(r.Warnings, "profile_schema_unsupported")
				continue
			}
			if refs[profile.Reference] {
				r.Warnings = append(r.Warnings, "conflicting_profile_references")
			}
			refs[profile.Reference] = true
			r.Profiles = append(r.Profiles, profile)
		}
		return finish()
	}
	// A missing layer would change a merged Netplan view; don't parse an incomplete snapshot.
	if incomplete {
		r.Status = "unavailable"
		return finish()
	}
	dir, err := os.MkdirTemp("", "cythsec-read-config-*")
	if err != nil {
		r.Status = "unavailable"
		r.Warnings = append(r.Warnings, "workspace_unavailable")
		return finish()
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.Abs(dir)
	if err != nil {
		r.Status = "unavailable"
		r.Warnings = append(r.Warnings, "workspace_unavailable")
		return finish()
	}
	var raw []byte
	if backend == "netplan" {
		for _, file := range files {
			dest := filepath.Join(dir, strings.TrimPrefix(file.meta.Path, "/"))
			if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				break
			}
			if err = os.WriteFile(dest, file.content, 0600); err != nil {
				break
			}
		}
		if err == nil {
			raw, err = p.execute(ctx, "netplan", []string{"get", "--root-dir", dir, "network.ethernets"}, "", dir)
		}
		if err == nil {
			raw, err = p.execute(ctx, "python3", []string{"-I", "-c", netplanProjection}, string(raw), dir)
		}
		if err == nil {
			r.Profiles, err = parseNetplanProjection(raw, r.Sources)
		}
	} else {
		file := filepath.Join(dir, "network")
		if err = os.WriteFile(file, files[0].content, 0600); err == nil {
			raw, err = p.execute(ctx, "uci", []string{"-s", "export", file}, "", dir)
		}
		if err == nil {
			r.Profiles, err = parseUCIExport(raw, files[0].meta.ID)
		}
	}
	if err != nil {
		r.Status = "unavailable"
		r.Profiles = []PersistentProfile{}
		r.Warnings = append(r.Warnings, "native_read_unavailable")
	}
	for _, profile := range r.Profiles {
		for _, state := range profile.FieldStates {
			if state == "unsupported" {
				r.Status = "partial"
			}
		}
	}
	return finish()
}
func (p *PersistentReader) execute(ctx context.Context, tool string, args []string, input, dir string) ([]byte, error) {
	path, err := p.find(tool)
	if err != nil {
		return nil, err
	}
	return p.run(ctx, path, args, input, dir)
}
func (p *PersistentReader) readSources(ctx context.Context, backend string) ([]sourceFile, bool) {
	files := []sourceFile{}
	incomplete := false
	total := 0
	read := func(public, storage string) {
		if ctx.Err() != nil || len(files) >= 64 {
			incomplete = true
			return
		}
		file := sourceFile{meta: ConfigSource{Path: public, Storage: storage, State: "unavailable"}}
		path := filepath.Join(p.root, strings.TrimPrefix(public, "/"))
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err == nil {
			defer f.Close()
			st, e := f.Stat()
			file.meta.Safety = sourceSafety(st, backend)
			if e == nil && st.Mode().IsRegular() && st.Size() <= 1024*1024 {
				file.content, err = io.ReadAll(io.LimitReader(f, 1024*1024+1))
				if err == nil && len(file.content) <= 1024*1024 && total+len(file.content) <= 2*1024*1024 {
					after, ae := f.Stat()
					current, ce := os.Lstat(path)
					stable := ae == nil && ce == nil && int64(len(file.content)) == after.Size() && stableSource(st, after, current)
					file.meta.Safety.Stable = &stable
					if !stable {
						file.meta.Safety.Status = "blocked"
						file.meta.Safety.Codes = append(file.meta.Safety.Codes, "source_changed_during_read")
					} else {
						file.meta.State = "read"
						file.meta.VersionTag = p.fingerprint(file.content)
						file.meta.Bytes = len(file.content)
						total += len(file.content)
					}
				}
			}
		}
		if file.meta.State != "read" {
			incomplete = true
			file.content = nil
		}
		file.meta.ID = p.fingerprint([]byte(public + "\x00" + file.meta.VersionTag))
		files = append(files, file)
	}
	if backend == "openwrt" {
		read("/etc/config/network", "persistent")
		return files, incomplete
	}
	dirs := []struct{ path, storage string }{{"/lib/netplan", "vendor"}, {"/etc/netplan", "persistent"}, {"/run/netplan", "runtime"}}
	ext := ".yaml"
	if backend == "networkmanager" {
		dirs = []struct{ path, storage string }{{"/usr/lib/NetworkManager/system-connections", "vendor"}, {"/etc/NetworkManager/system-connections", "persistent"}, {"/run/NetworkManager/system-connections", "runtime"}}
		ext = ".nmconnection"
	}
	for _, d := range dirs {
		if ctx.Err() != nil {
			incomplete = true
			break
		}
		f, err := os.OpenFile(filepath.Join(p.root, strings.TrimPrefix(d.path, "/")), os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			incomplete = true
			continue
		}
		entries, e := f.ReadDir(65)
		f.Close()
		if e != nil && !errors.Is(e, io.EOF) {
			incomplete = true
			continue
		}
		if len(entries) > 64 {
			incomplete = true
			entries = entries[:64]
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ext) {
				read(d.path+"/"+entry.Name(), d.storage)
			} else if backend == "networkmanager" && !entry.IsDir() {
				incomplete = true
			}
		}
	}
	return files, incomplete
}

func (p *PersistentReader) fingerprint(raw []byte) string {
	mac := hmac.New(sha256.New, p.fingerprintKey)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}
