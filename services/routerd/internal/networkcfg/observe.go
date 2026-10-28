package networkcfg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

var ErrObservationBusy = errors.New("network observation busy")
var errProbeLimit = errors.New("probe output limit")

type Owner struct {
	Backend   string `json:"backend"`
	Reference string `json:"reference"`
	Source    string `json:"source"`
}
type ObservedInterface struct {
	Device       string            `json:"device"`
	Kind         string            `json:"kind"`
	Up           bool              `json:"up"`
	MTU          *int              `json:"mtu"`
	Addresses    []string          `json:"addresses"`
	DNS          []string          `json:"dns"`
	Search       []string          `json:"search"`
	Routes       []Route           `json:"routes"`
	Owners       []Owner           `json:"owners"`
	Restrictions []string          `json:"restrictions,omitempty"`
	Known        map[string]bool   `json:"known"`
	Sources      map[string]string `json:"sources"`
}
type ManagerObservation struct {
	Backend     string `json:"backend"`
	State       string `json:"state"`
	ToolVersion string `json:"tool_version"`
	Diagnostic  string `json:"diagnostic"`
}
type Observation struct {
	ID                 string               `json:"id"`
	Platform           string               `json:"platform"`
	StartedAt          time.Time            `json:"started_at"`
	ObservedAt         time.Time            `json:"observed_at"`
	InventoryAvailable bool                 `json:"inventory_available"`
	Status             string               `json:"status"`
	Managers           []ManagerObservation `json:"managers"`
	Interfaces         []ObservedInterface  `json:"interfaces"`
	Warnings           []string             `json:"warnings"`
}
type nativeInterface struct {
	Device                string
	DNS, Search           []string
	DNSKnown, SearchKnown bool
	Owner                 Owner
	Restriction           string
}
type observationSource struct {
	platform string
	kernel   func() ([]ObservedInterface, error)
	query    func(context.Context, string) ([]byte, error)
}
type Observer struct {
	source observationSource
	gate   chan struct{}
}

func NewObserver() *Observer {
	return newObserver(observationSource{runtime.GOOS, kernelObservation, queryHost})
}
func newObserver(s observationSource) *Observer { return &Observer{s, make(chan struct{}, 1)} }
func (o *Observer) Capture(ctx context.Context) (Observation, error) {
	select {
	case o.gate <- struct{}{}:
		defer func() { <-o.gate }()
	default:
		return Observation{}, ErrObservationBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := Observation{Platform: o.source.platform, StartedAt: time.Now().UTC(), Status: "partial", Managers: []ManagerObservation{}, Interfaces: []ObservedInterface{}, Warnings: []string{"non_atomic_runtime_snapshot", "persistent_configuration_not_read"}}
	interfaces, err := o.source.kernel()
	if err == nil {
		result.InventoryAvailable = true
		result.Interfaces = interfaces
		for i := range result.Interfaces {
			p := &result.Interfaces[i]
			if p.Known == nil {
				p.Known = map[string]bool{}
			}
			if p.Sources == nil {
				p.Sources = map[string]string{}
			}
			if p.Owners == nil {
				p.Owners = []Owner{}
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "kernel_inventory_unavailable")
	}
	if o.source.platform != "linux" {
		for _, backend := range []string{"networkmanager", "networkd", "openwrt"} {
			result.Managers = append(result.Managers, ManagerObservation{Backend: backend, State: "unsupported", Diagnostic: "unsupported_platform"})
		}
	} else {
		merge := func(items []nativeInterface) {
			for _, item := range items {
				for i := range result.Interfaces {
					p := &result.Interfaces[i]
					if p.Device != item.Device {
						continue
					}
					p.Owners = append(p.Owners, item.Owner)
					if item.Restriction != "" {
						p.Restrictions = append(p.Restrictions, item.Restriction)
					}
					if len(p.Owners) > 1 {
						p.DNS = nil
						p.Search = nil
						p.Known["dns"] = false
						p.Known["search"] = false
						p.Sources["dns"] = "conflicting_owners"
						p.Sources["search"] = "conflicting_owners"
						continue
					}
					if item.DNSKnown && !p.Known["dns"] {
						p.DNS = item.DNS
						p.Known["dns"] = true
						p.Sources["dns"] = item.Owner.Source
					}
					if item.SearchKnown && !p.Known["search"] {
						p.Search = item.Search
						p.Known["search"] = true
						p.Sources["search"] = item.Owner.Source
					}
				}
			}
		}
		nm := ManagerObservation{Backend: "networkmanager", State: "unavailable", Diagnostic: "probe_unavailable"}
		nmState, nmErr := o.source.query(ctx, "nm_active")
		if strings.TrimSpace(string(nmState)) == "active" && nmErr == nil {
			nm.State = "partial"
			nm.Diagnostic = "probe_unavailable"
			if raw, e := o.source.query(ctx, "nm_devices"); e == nil {
				if parsed, e := parseNM(raw); e == nil {
					nm.State = "active"
					nm.Diagnostic = ""
					merge(parsed)
				} else {
					nm.Diagnostic = "unsupported_schema"
				}
			}
			if raw, e := o.source.query(ctx, "nm_version"); e == nil {
				nm.ToolVersion = readVersion(raw, "nmcli")
			}
		} else if value := strings.TrimSpace(string(nmState)); value == "inactive" {
			nm.State = "inactive"
			nm.Diagnostic = value
		} else if value == "failed" || value == "unknown" {
			nm.State = "unavailable"
			nm.Diagnostic = value
		}

		result.Managers = append(result.Managers, nm)
		nd := ManagerObservation{Backend: "networkd", State: "unavailable", Diagnostic: "probe_unavailable"}
		state, stateErr := o.source.query(ctx, "networkd_active")
		switch strings.TrimSpace(string(state)) {
		case "active":
			if stateErr == nil {
				nd.State = "partial"
				nd.Diagnostic = "unsupported_schema"
				if raw, e := o.source.query(ctx, "networkd_version"); e == nil {
					nd.ToolVersion = readVersion(raw, "systemd")
				}
				if raw, e := o.source.query(ctx, "networkd_status"); e == nil {
					if parsed, e := parseNetworkd(raw); e == nil {
						nd.State = "active"
						nd.Diagnostic = ""
						merge(parsed)
					}
				}
			}
		case "inactive":
			nd.State = "inactive"
			nd.Diagnostic = "inactive"
		case "failed", "unknown":
			nd.State = "unavailable"
			nd.Diagnostic = strings.TrimSpace(string(state))
		}
		result.Managers = append(result.Managers, nd)
		ow := ManagerObservation{Backend: "openwrt", State: "unavailable", Diagnostic: "probe_unavailable"}
		if raw, e := o.source.query(ctx, "openwrt_dump"); e == nil {
			if parsed, e := parseOpenWrt(raw); e == nil {
				ow.State = "active"
				ow.Diagnostic = ""
				merge(parsed)
			} else {
				ow.State = "partial"
				ow.Diagnostic = "unsupported_schema"
			}
		}
		result.Managers = append(result.Managers, ow)
		// The native FIB main table is compared, not a guessed sum of manager declarations.
		routes := map[string][]Route{}
		routesKnown := true
		for _, q := range []struct {
			id string
			v4 bool
		}{{"ip4_routes", true}, {"ip6_routes", false}} {
			raw, e := o.source.query(ctx, q.id)
			if e != nil {
				routesKnown = false
				continue
			}
			parsed, e := parseIPRoutes(raw, q.v4)
			if e != nil {
				routesKnown = false
				continue
			}
			for device, items := range parsed {
				routes[device] = append(routes[device], items...)
			}
		}
		if !routesKnown {
			result.Warnings = append(result.Warnings, "main_routes_unavailable")
		} else {
			for i := range result.Interfaces {
				p := &result.Interfaces[i]
				p.Routes = routes[p.Device]
				if p.Routes == nil {
					p.Routes = []Route{}
				}
				p.Known["routes"] = true
				p.Sources["routes"] = "iproute2_main_table"
			}
		}
	}
	complete := result.InventoryAvailable && len(result.Warnings) == 2
	for _, p := range result.Interfaces {
		if !p.Known["mtu"] || !p.Known["addresses"] {
			complete = false
		}
	}
	for _, m := range result.Managers {
		if m.State == "partial" || m.State == "unavailable" || m.State == "unsupported" {
			complete = false
		}
	}
	if complete {
		result.Status = "observed"
	}
	sort.Slice(result.Interfaces, func(i, j int) bool { return result.Interfaces[i].Device < result.Interfaces[j].Device })
	if ctx.Err() != nil {
		result.Status = "partial"
		result.Warnings = append(result.Warnings, "observation_timeout")
	}
	result.ObservedAt = time.Now().UTC()
	raw, _ := json.Marshal(result)
	result.ID = hashBytes(raw)
	return result, nil
}
func kernelObservation() ([]ObservedInterface, error) {
	devices, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	if len(devices) > 512 {
		return nil, errors.New("kernel inventory limit")
	}
	result := make([]ObservedInterface, 0, len(devices))
	for _, device := range devices {
		p := ObservedInterface{Device: device.Name, Kind: "unknown", Up: device.Flags&net.FlagUp != 0, Owners: []Owner{}, Known: map[string]bool{}, Sources: map[string]string{}}
		if device.Flags&net.FlagLoopback != 0 {
			p.Kind = "loopback"
		} else if runtime.GOOS == "linux" {
			p.Kind = linuxKind(device.Name)
		}
		if device.MTU > 0 {
			value := device.MTU
			p.MTU = &value
			p.Known["mtu"] = true
			p.Sources["mtu"] = "kernel"
		}
		addresses, e := device.Addrs()
		if e == nil && len(addresses) <= 256 {
			p.Addresses = []string{}
			p.Known["addresses"] = true
			p.Sources["addresses"] = "kernel"
			for _, address := range addresses {
				if prefix, e := netip.ParsePrefix(address.String()); e == nil {
					p.Addresses = append(p.Addresses, prefix.String())
				} else {
					p.Known["addresses"] = false
				}
			}
		}
		result = append(result, p)
	}
	return result, nil
}
func linuxKind(device string) string {
	if !deviceName.MatchString(device) {
		return "unknown"
	}
	for _, q := range []struct{ path, kind string }{{filepath.Join("/sys/class/net", device, "master"), "master_member"}, {filepath.Join("/sys/class/net", device, "wireless"), "wireless"}, {filepath.Join("/sys/class/net", device, "phy80211"), "wireless"}, {filepath.Join("/sys/class/net", device, "bridge"), "bridge"}, {filepath.Join("/sys/class/net", device, "bonding"), "bond"}, {filepath.Join("/proc/net/vlan", device), "vlan"}, {filepath.Join("/sys/class/net", device, "tun_flags"), "tunnel"}} {
		if _, err := os.Stat(q.path); err == nil {
			return q.kind
		} else if !os.IsNotExist(err) {
			return "unknown"
		}
	}
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", device, "type"))
	if err != nil || strings.TrimSpace(string(raw)) != "1" {
		return "unknown"
	}
	if _, err = os.Stat(filepath.Join("/sys/class/net", device, "device")); err == nil {
		return "physical_ethernet"
	}
	return "virtual_or_unknown"
}

var readQueries = map[string]struct {
	tool string
	args []string
}{
	"nm_active":        {"systemctl", []string{"--no-pager", "is-active", "NetworkManager"}},
	"nm_devices":       {"nmcli", []string{"-t", "-m", "multiline", "-f", "GENERAL.DEVICE,GENERAL.TYPE,GENERAL.STATE,GENERAL.CON-PATH,GENERAL.MTU,IP4,IP6", "device", "show"}},
	"nm_version":       {"nmcli", []string{"--version"}},
	"networkd_active":  {"systemctl", []string{"--no-pager", "is-active", "systemd-networkd"}},
	"networkd_version": {"networkctl", []string{"--version"}},
	"networkd_status":  {"busctl", []string{"--system", "--auto-start=no", "--allow-interactive-authorization=no", "--timeout=1", "--json=short", "call", "org.freedesktop.network1", "/org/freedesktop/network1", "org.freedesktop.network1.Manager", "Describe"}},
	"openwrt_dump":     {"ubus", []string{"call", "network.interface", "dump"}},
	"ip4_routes":       {"ip", []string{"-j", "-4", "route", "show", "table", "main"}},
	"ip6_routes":       {"ip", []string{"-j", "-6", "route", "show", "table", "main"}},
}

func queryHost(ctx context.Context, id string) ([]byte, error) {
	q, ok := readQueries[id]
	if !ok {
		return nil, errors.New("query not allowed")
	}
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		path := filepath.Join(dir, q.tool)
		if st, e := os.Stat(path); e == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
			return captureReadCommand(ctx, path, q.args)
		}
	}
	return nil, errors.New("probe unavailable")
}

type limitedProbeBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedProbeBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.overflow = true
		return 0, errProbeLimit
	}
	return b.buffer.Write(p)
}
func captureReadCommand(ctx context.Context, path string, args []string) ([]byte, error) {
	return captureProbeCommand(ctx, path, args, "", "")
}

func captureProbeCommand(ctx context.Context, path string, args []string, input, dir string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	cmd.Stdin = strings.NewReader(input)
	cmd.Dir = dir
	if dir != "" {
		cmd.Env = append(cmd.Env, "HOME="+dir, "TMPDIR="+dir)
	}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 100 * time.Millisecond
	output := &limitedProbeBuffer{limit: 1024 * 1024}
	cmd.Stdout = output
	err := cmd.Run()
	if output.overflow {
		return nil, errProbeLimit
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return output.buffer.Bytes(), err
}
func readVersion(raw []byte, prefix string) string {
	line := strings.SplitN(string(raw), "\n", 2)[0]
	if len(line) > 256 || !strings.HasPrefix(line, prefix) {
		return ""
	}
	return versionPattern.FindString(line)
}

func hashBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
