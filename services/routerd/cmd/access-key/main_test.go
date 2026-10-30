package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProvisionIsPrivateAndDoesNotOverwrite(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "access-key")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	path := filepath.Join(t.TempDir(), "access.json")
	args := []string{"-name", "qa-reader", "-out", path}
	out, err := exec.Command(binary, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.TrimSpace(string(out))
	if len(credential) != 43 {
		t.Fatal("unexpected credential entropy")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("policy not private")
	}
	digest := sha256.Sum256([]byte(credential))
	var body struct {
		Principals []struct {
			SHA256 string `json:"sha256"`
		} `json:"principals"`
	}
	if json.Unmarshal(data, &body) != nil || len(body.Principals) != 1 || body.Principals[0].SHA256 != hex.EncodeToString(digest[:]) || strings.Contains(string(data), credential) {
		t.Fatal("policy does not contain only credential digest")
	}
	if err := exec.Command(binary, args...).Run(); err == nil {
		t.Fatal("existing policy overwritten")
	}
	again, _ := os.ReadFile(path)
	if string(data) != string(again) {
		t.Fatal("existing policy changed")
	}
}
