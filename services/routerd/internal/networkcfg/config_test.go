package networkcfg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() Config {
	return Config{Backend: "netplan", Interfaces: []Interface{{ID: "lan", Device: "eth0", MTU: 1500, Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, DNS: []string{"192.0.2.53", "2001:db8::53"}, Search: []string{"example.test"}, Routes: []Route{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Metric: 100}, {Destination: "::/0", Gateway: "2001:db8::1", Metric: 100}}}}}
}
func TestCompileNativePreviews(t *testing.T) {
	for _, backend := range []string{"netplan", "networkmanager", "openwrt"} {
		c := fixture()
		c.Backend = backend
		p, err := Compile(c)
		if err != nil {
			t.Fatal(err)
		}
		if p.Stage != "validated_preview" || len(p.Digest) != 64 || len(p.Artifacts) != 1 {
			t.Fatal("missing preview identity")
		}
		p2, _ := Compile(c)
		if p.Digest != p2.Digest || p.Artifacts[0].Content != p2.Artifacts[0].Content {
			t.Fatal("non-deterministic preview")
		}
		text := p.Artifacts[0].Content
		switch backend {
		case "netplan":
			var data map[string]any
			if json.Unmarshal([]byte(text), &data) != nil {
				t.Fatal("invalid YAML/JSON")
			}
			if !strings.Contains(text, `"networkd"`) || !strings.Contains(text, `"accept-ra": false`) {
				t.Fatal(text)
			}
		case "networkmanager":
			for _, v := range []string{"[ipv4]", "[ipv6]", "method=manual", "address1=192.0.2.10/24", "route1=::/0,2001:db8::1,100", "dns-search=example.test"} {
				if !strings.Contains(text, v) {
					t.Fatal(v)
				}
			}
		case "openwrt":
			for _, v := range []string{"config interface 'cythsec_lan'", "list ipaddr '192.0.2.10/24'", "config route6 'cythsec_lan_2'", "option interface 'cythsec_lan'"} {
				if !strings.Contains(text, v) {
					t.Fatal(v)
				}
			}
		}
	}
}
func TestRejectInvalidAndInjectedNetworkValues(t *testing.T) {
	mutations := []func(*Config){
		func(c *Config) { c.Interfaces[0].Routes[0].Gateway = "192.0.2.10" },
		func(c *Config) { c.Interfaces[0].Routes[0].Gateway = "192.0.2.255" },
		func(c *Config) { c.Interfaces[0].Routes[0].Gateway = "169.254.1.1" }, func(c *Config) { c.Backend = "shell" }, func(c *Config) { c.Interfaces[0].ID = "lan';reboot" }, func(c *Config) { c.Interfaces[0].Device = "lo" }, func(c *Config) { c.Interfaces[0].MTU = 1000 }, func(c *Config) { c.Interfaces[0].Addresses = []string{"192.0.2.0/24"} }, func(c *Config) { c.Interfaces[0].Addresses = []string{"127.0.0.1/8"} }, func(c *Config) { c.Interfaces[0].DNS = []string{"8.8.8.8\nreboot"} }, func(c *Config) { c.Interfaces[0].Search = []string{"x;reboot"} }, func(c *Config) { c.Interfaces[0].Routes[0].Gateway = "198.51.100.1" }, func(c *Config) { c.Interfaces[0].Routes[0].Destination = "192.0.2.10/24" }, func(c *Config) { c.Interfaces[0].Routes[0].Gateway = "2001:db8::1" }, func(c *Config) { c.Interfaces = append(c.Interfaces, c.Interfaces[0]) }}
	for i, mutate := range mutations {
		c := fixture()
		mutate(&c)
		if _, err := Compile(c); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}
func TestStoreDurabilityConflictAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = Open(dir); err == nil {
		t.Fatal("two writers opened store")
	}
	state, err := s.Save(0, fixture())
	if err != nil || state.Revision != 1 || state.Stage != "draft_saved" {
		t.Fatal(state, err)
	}
	state.Config.Interfaces[0].Addresses[0] = "mutated"
	if s.Read().Config.Interfaces[0].Addresses[0] == "mutated" {
		t.Fatal("caller changed stored state")
	}
	if _, err = s.Save(0, fixture()); !errors.Is(err, ErrConflict) {
		t.Fatal("lost update accepted")
	}
	s.Close()
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Read().Revision != 1 {
		t.Fatal("state lost on restart")
	}
	reopened.Close()
	if err = os.WriteFile(filepath.Join(dir, "desired.json"), []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil {
		t.Fatal("corrupt store opened")
	}
	os.Remove(filepath.Join(dir, "desired.json"))
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}
