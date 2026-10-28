package networkcfg

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const nmSample = `GENERAL.DEVICE:eth0
GENERAL.TYPE:ethernet
GENERAL.MTU:1500
GENERAL.STATE:100 (connected)
GENERAL.CON-PATH:/org/freedesktop/NetworkManager/ActiveConnection/7
IP4.ADDRESS[1]:192.0.2.10/24
IP4.DNS[1]:192.0.2.53
IP4.DOMAIN[1]:example.test
IP6.DNS[1]:2001\:db8\:\:53
`

func fakeKernel() ([]ObservedInterface, error) {
	mtu := 1500
	return []ObservedInterface{{Device: "eth0", Kind: "physical_ethernet", Up: true, MTU: &mtu, Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, Known: map[string]bool{"mtu": true, "addresses": true}, Sources: map[string]string{"mtu": "kernel", "addresses": "kernel"}}}, nil
}
func fakeSource() observationSource {
	return observationSource{"linux", fakeKernel, func(ctx context.Context, id string) ([]byte, error) {
		switch id {
		case "nm_active":
			return []byte("active\n"), nil
		case "nm_devices":
			return []byte(nmSample), nil
		case "nm_version":
			return []byte("nmcli tool, version 1.46.2\n"), nil
		case "networkd_active":
			return []byte("inactive"), errors.New("exit 3")
		case "ip4_routes":
			return []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":100}]`), nil
		case "ip6_routes":
			return []byte(`[{"dst":"default","gateway":"2001:db8::1","dev":"eth0","metric":100}]`), nil
		}
		return nil, errors.New("not installed")
	}}
}
func TestObserveAndCompareRuntime(t *testing.T) {
	o, err := newObserver(fakeSource()).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(o.ID) != 64 || o.ObservedAt.Before(o.StartedAt) || !o.InventoryAvailable {
		t.Fatal("observation evidence missing")
	}
	p := o.Interfaces[0]
	if !p.Known["dns"] || len(p.DNS) != 2 || len(p.Owners) != 1 || p.Owners[0].Backend != "networkmanager" {
		t.Fatalf("bad projection: %+v", p)
	}
	c := fixture()
	c.Backend = "networkmanager"
	report, err := Compare(c, o)
	if err != nil {
		t.Fatal(err)
	}
	if report.CanApply || report.Status != "review_required" || len(report.Differences) != 5 {
		t.Fatal("read snapshot granted apply")
	}
	for _, d := range report.Differences {
		if d.State != "same" {
			t.Fatalf("same runtime values not recognized: %+v", d)
		}
	}
	c.Interfaces[0].DNS = []string{"198.51.100.53"}
	changed, _ := Compare(c, o)
	if changed.Differences[2].State != "different" {
		t.Fatal("DNS change not reported")
	}
	o.Interfaces[0].Known["dns"] = false
	unknown, _ := Compare(c, o)
	if unknown.Differences[2].State != "unknown" || unknown.Differences[2].Current != nil {
		t.Fatal("unknown became zero/empty")
	}
}
func TestUnavailablePlatformDoesNotRunCommands(t *testing.T) {
	source := fakeSource()
	source.platform = "darwin"
	source.query = func(context.Context, string) ([]byte, error) {
		t.Fatal("Linux probe on unsupported platform")
		return nil, nil
	}
	o, err := newObserver(source).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := Compare(fixture(), o)
	if p.Status != "blocked" || p.CanApply || p.Differences[2].State != "unknown" {
		t.Fatal("unsupported platform looked ready")
	}
}
func TestNativeParsersAndSensitiveProjection(t *testing.T) {
	networkd := []byte(`{"Interfaces":[{"Name":"eth0","Index":2,"MTU":1500,"AdministrativeState":"configured","NetworkFile":"/run/systemd/network/10-netplan-eth0.network","DNS":[{"Address":[192,0,2,53]}],"SearchDomains":[{"Domain":"Example.Test"}],"DHCPv4Client":{"secret":"test-sensitive-not-returned"}}]}`)
	wrapped, _ := json.Marshal(map[string]any{"type": "s", "data": []string{string(networkd)}})
	parsed, err := parseNetworkd(wrapped)
	if err != nil || parsed[0].Owner.Backend != "networkd" || !parsed[0].DNSKnown {
		t.Fatal(parsed, err)
	}
	scoped := strings.Replace(string(networkd), `"Address":[192,0,2,53]`, `"Address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,83],"InterfaceIndex":2`, 1)
	scopedValues, scopeErr := parseNetworkd([]byte(scoped))
	if scopeErr != nil || scopedValues[0].DNS[0] != "fe80::53%2" {
		t.Fatal("DNS scope lost", scopeErr)
	}
	ow := []byte(`{"interface":[{"interface":"wan","device":"eth0","l3_device":"eth0","proto":"static","dns-server":[],"dns-search":[],"data":{"password":"test-sensitive-not-returned"}}]}`)
	openwrt, err := parseOpenWrt(ow)
	if err != nil || !openwrt[0].DNSKnown || len(openwrt[0].DNS) != 0 {
		t.Fatal(openwrt, err)
	}
	missing, err := parseOpenWrt([]byte(`{"interface":[{"interface":"wan","device":"eth0","proto":"static"}]}`))
	if err != nil || missing[0].DNSKnown {
		t.Fatal("missing array became empty known DNS")
	}
	raw, _ := json.Marshal(append(parsed, openwrt...))
	if strings.Contains(string(raw), "sensitive") {
		t.Fatal("unexpected native fields leaked")
	}
	for _, input := range []string{`{}`, `{"Interfaces":null}`, `{"type":"s","data":["{}"],"Interfaces":[]}`, `{"Interfaces":[{"Name":"eth0","Index":2,"AdministrativeState":"configured","NetworkFile":"a","DNS":[{"Address":[999]}]}]}`} {
		if _, err := parseNetworkd([]byte(input)); err == nil {
			t.Fatal("invalid networkd schema accepted")
		}
	}
	if _, err := parseIPRoutes([]byte(`[{"dst":"default","nexthops":[{"dev":"eth0"}]}]`), true); err == nil {
		t.Fatal("ECMP silently reduced to ordinary route")
	}
	if _, err := parseIPRoutes([]byte(`[{"dst":"192.0.2.53","dev":"eth0"}]`), true); err != nil {
		t.Fatal("host route without prefix rejected", err)
	}
}
func TestConflictingOwnersAndUnknownInventoryBlock(t *testing.T) {
	source := fakeSource()
	run := source.query
	source.query = func(ctx context.Context, id string) ([]byte, error) {
		if id == "openwrt_dump" {
			return []byte(`{"interface":[{"interface":"lan","device":"eth0","proto":"static","dns-server":["198.51.100.53"],"dns-search":[]}]}`), nil
		}
		return run(ctx, id)
	}
	o, _ := newObserver(source).Capture(context.Background())
	if o.Interfaces[0].Known["dns"] {
		t.Fatal("conflicting DNS selected as truth")
	}
	p, _ := Compare(fixture(), o)
	if p.Status != "blocked" {
		t.Fatal("multiple owners not blocked")
	}
	source.kernel = func() ([]ObservedInterface, error) { return nil, errors.New("unavailable") }
	o, _ = newObserver(source).Capture(context.Background())
	p, _ = Compare(fixture(), o)
	for _, issue := range p.Issues {
		if issue.Code == "device_missing" {
			t.Fatal("missing inventory asserted absent device")
		}
	}
	if p.Status != "blocked" {
		t.Fatal("unknown inventory ready")
	}
}
func TestObserverSerializesCaptures(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	source := fakeSource()
	source.platform = "darwin"
	source.kernel = func() ([]ObservedInterface, error) { close(entered); <-release; return fakeKernel() }
	observer := newObserver(source)
	done := make(chan struct{})
	go func() { defer close(done); observer.Capture(context.Background()) }()
	<-entered
	if _, err := observer.Capture(context.Background()); !errors.Is(err, ErrObservationBusy) {
		t.Fatal("parallel native capture accepted")
	}
	close(release)
	<-done
}
func TestCaptureReadCommandLimits(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=TestProbeHelperProcess", "--", "cythsec-observer-test", "large"}
	if _, err = captureReadCommand(context.Background(), path, args); !errors.Is(err, errProbeLimit) {
		t.Fatal("output limit not enforced", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	args[len(args)-1] = "wait"
	if _, err = captureReadCommand(ctx, path, args); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline not enforced", err)
	}
	if _, err = queryHost(context.Background(), "apply"); err == nil {
		t.Fatal("unregistered command accepted")
	}
}
func TestProbeHelperProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "cythsec-observer-test" {
		return
	}
	if os.Args[len(os.Args)-1] == "large" {
		os.Stdout.Write(make([]byte, 1024*1024+1))
		os.Exit(0)
	}
	time.Sleep(3 * time.Second)
	os.Exit(0)
}

func TestIndirectL3ParentCannotBeTakenOverAsOrdinaryPort(t *testing.T) {
	source := fakeSource()
	run := source.query
	source.query = func(ctx context.Context, id string) ([]byte, error) {
		if id == "nm_active" {
			return []byte("inactive"), nil
		}
		if id == "openwrt_dump" {
			return []byte(`{"interface":[{"interface":"wan","proto":"pppoe","device":"eth0","l3_device":"pppoe-wan","dns-server":[],"dns-search":[]}]}`), nil
		}
		return run(ctx, id)
	}
	o, err := newObserver(source).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := fixture()
	c.Backend = "openwrt"
	p, err := Compare(c, o)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range p.Issues {
		if issue.Code == "layered_device_relation" {
			found = true
		}
	}
	if p.Status != "blocked" || !found {
		t.Fatal("physical parent accepted as plain L3 interface")
	}
}

func TestUnknownServiceStateIsNotAnInactiveClaim(t *testing.T) {
	source := fakeSource()
	run := source.query
	source.query = func(ctx context.Context, id string) ([]byte, error) {
		if id == "nm_active" || id == "networkd_active" {
			return []byte("unknown"), errors.New("unit not known")
		}
		return run(ctx, id)
	}
	result, err := newObserver(source).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range result.Managers {
		if (m.Backend == "networkmanager" || m.Backend == "networkd") && m.State != "unavailable" {
			t.Fatal("unknown service state became inactive", m)
		}
	}
}
