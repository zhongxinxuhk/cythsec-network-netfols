//go:build netplan_yaml

package networkcfg

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Supplemental YAML-reader integration: requires Python with PyYAML. The default
// pure trace tests remain stdlib-only and do not depend on a host YAML install.
func TestNetplanBoundedYAMLSourceReader(t *testing.T) {
	python := os.Getenv("CYTHSEC_NETPLAN_TEST_PYTHON")
	if python == "" {
		python = "python3"
	}
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, source string
		success      bool
	}{
		{"scalar", "network:\n  ethernets:\n    lan:\n      mtu: 1500\n      auth:\n        password: fixture-private\n", true},
		{"duplicate", "network:\n  ethernets:\n    lan:\n      mtu: 1400\n      mtu: 1500\n", false},
		{"alias", "network: &alias\n  ethernets: *alias\n", false},
		{"tag", "network: !override {}\n", false},
		{"depth", "network: " + strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40), false},
		{"bytes", strings.Repeat("x", 1024*1024+1), false},
		{"nodes", "network:\n  ethernets:\n    lan:\n      auth: [" + strings.Repeat("x,", 8200) + "x]\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "etc/netplan/10.yaml")
			os.MkdirAll(filepath.Dir(path), 0700)
			os.WriteFile(path, []byte(tc.source), 0600)
			input, _ := json.Marshal(map[string]any{"sources": []map[string]string{{"id": id, "path": "/etc/netplan/10.yaml"}}, "merged": map[string]any{"lan": map[string]any{"mtu": 1500}}})
			cmd := exec.Command(python, "-I", "-c", netplanProjection, "--source-trace", root)
			cmd.Stdin = bytes.NewReader(input)
			raw, err := cmd.CombinedOutput()
			if (err == nil) != tc.success || bytes.Contains(raw, []byte("fixture-private")) || (!tc.success && len(raw) != 0) {
				t.Fatal("reader result/error leaked or misclassified", err, string(raw))
			}
			if tc.success && !bytes.Contains(raw, []byte("projection_matches")) {
				t.Fatal("field not traced", string(raw))
			}
		})
	}
}

func TestNetplanShadowedInvalidYAMLIsNotParsed(t *testing.T) {
	python := os.Getenv("CYTHSEC_NETPLAN_TEST_PYTHON")
	if python == "" {
		python = "python3"
	}
	root := t.TempDir()
	for path, content := range map[string]string{"lib/netplan/10.yaml": "network: [invalid fixture-private", "etc/netplan/10.yaml": "network:\n  ethernets:\n    lan:\n      mtu: 1500\n"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input, _ := json.Marshal(map[string]any{"sources": []map[string]string{{"id": strings.Repeat("a", 64), "path": "/lib/netplan/10.yaml"}, {"id": strings.Repeat("b", 64), "path": "/etc/netplan/10.yaml"}}, "merged": map[string]any{"lan": map[string]any{"mtu": 1500}}})
	cmd := exec.Command(python, "-I", "-c", netplanProjection, "--source-trace", root)
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.CombinedOutput()
	if err != nil || bytes.Contains(raw, []byte("fixture-private")) {
		t.Fatal(err, string(raw))
	}
	var result struct {
		Active   []string `json:"active_source_ids"`
		Shadowed []string `json:"shadowed_source_ids"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Active) != 1 || result.Active[0] != strings.Repeat("b", 64) || len(result.Shadowed) != 1 || result.Shadowed[0] != strings.Repeat("a", 64) {
		t.Fatal(string(raw))
	}
}
