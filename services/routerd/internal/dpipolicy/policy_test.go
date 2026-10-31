package dpipolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPolicyEnablesEveryModule(t *testing.T) {
	policy := Default()
	if policy.SchemaVersion != SchemaVersion || !policy.Enabled || policy.Intensity != "standard" {
		t.Fatalf("unexpected default: %+v", policy)
	}
	if len(policy.Modules) != len(Modules) {
		t.Fatalf("modules=%d catalog=%d", len(policy.Modules), len(Modules))
	}
	for _, module := range Modules {
		if enabled, ok := policy.Modules[module.Key]; !ok || enabled != module.DefaultEnabled {
			t.Fatalf("module %s missing or wrong default", module.Key)
		}
	}
}

func TestValidateRejectsTyposAndUnsafePaths(t *testing.T) {
	cases := []Policy{
		{SchemaVersion: 1, Intensity: "turbo", Modules: map[string]bool{"tls": true}},
		{SchemaVersion: 2, Intensity: "standard"},
		{SchemaVersion: 1, Intensity: "standard", Modules: map[string]bool{"typo": true}},
		{SchemaVersion: 1, Intensity: "standard", InspectBytes: intPtr(32)},
		{SchemaVersion: 1, Intensity: "deep", TLSDecrypt: TLSDecrypt{Enabled: true, KeylogFile: "relative.keys"}},
	}
	for i, policy := range cases {
		if err := Validate(policy); err == nil {
			t.Fatalf("case %d accepted invalid policy", i)
		}
	}
	good := Default()
	good.TLSDecrypt = TLSDecrypt{Enabled: true, KeylogFile: "/var/lib/cythsec/tls.keys"}
	if err := Validate(good); err != nil {
		t.Fatal(err)
	}
}

func intPtr(value int) *int { return &value }

func TestStoreRoundTripAndConflict(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dpi")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got := store.Read(); got.Revision != 0 || got.Policy.Intensity != "standard" {
		t.Fatalf("unexpected initial state: %+v", got)
	}
	next := Default()
	next.Intensity = "deep"
	next.Modules["smtp"] = false
	saved, err := store.Save(0, next)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.UpdatedAt == nil || saved.Policy.Modules["smtp"] {
		t.Fatalf("unexpected saved state: %+v", saved)
	}
	if _, err = store.Save(0, next); err != ErrConflict {
		t.Fatalf("stale revision accepted: %v", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := reopened.Read()
	if got.Revision != 1 || got.Policy.Intensity != "deep" || got.Policy.Modules["smtp"] {
		t.Fatalf("reloaded state mismatch: %+v", got)
	}
}

func TestStoreRejectsWorldReadablePolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dpi")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.Save(0, Default())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	raw, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil {
		t.Fatal("world-readable policy file accepted")
	}
}

func TestCatalogMatchesRegistryJSON(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "configs", "registry", "dpi-modules.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Modules []Module `json:"modules"`
	}
	if err = json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Modules) != len(Modules) {
		t.Fatalf("catalog=%d code=%d", len(catalog.Modules), len(Modules))
	}
	for index, want := range catalog.Modules {
		got := Modules[index]
		if got.Key != want.Key || got.Name != want.Name || got.Group != want.Group || got.Availability != want.Availability || got.DefaultEnabled != want.DefaultEnabled {
			t.Fatalf("module %d drift: got=%+v want=%+v", index, got, want)
		}
		if len(got.CatalogIDs) != len(want.CatalogIDs) {
			t.Fatalf("module %s catalog ids drift", got.Key)
		}
		for i := range got.CatalogIDs {
			if got.CatalogIDs[i] != want.CatalogIDs[i] {
				t.Fatalf("module %s catalog ids drift", got.Key)
			}
		}
	}
}
