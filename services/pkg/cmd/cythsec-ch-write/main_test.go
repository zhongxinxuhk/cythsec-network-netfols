package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runArgs(t *testing.T, args ...string) error {
	t.Helper()
	oldFlags, oldArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("cythsec-ch-write", flag.ContinueOnError)
	os.Args = append([]string{"cythsec-ch-write"}, args...)
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	return run()
}

func isolateConnectionEnvironment(t *testing.T) {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "CLICKHOUSE_") || key == "CYTHSEC_MIDDLEWARE_CONFIG" {
			old := os.Getenv(key)
			t.Setenv(key, old)
			os.Unsetenv(key)
		}
	}
}

func TestInboxCLIRejectsConflictingSourceOwnership(t *testing.T) {
	isolateConnectionEnvironment(t)
	for _, args := range [][]string{
		{"--input-dir", t.TempDir(), "--input", "-"},
		{"--input-dir", t.TempDir(), "--resume-file"},
		{"--input-dir", t.TempDir(), "--replay-only"},
		{"--scan-once"},
	} {
		spool := filepath.Join(t.TempDir(), "state")
		err := runArgs(t, append(args, "--spool", spool)...)
		if err == nil {
			t.Fatal("conflicting source ownership accepted", args)
		}
		if _, err := os.Stat(spool); !os.IsNotExist(err) {
			t.Fatal("invalid flags must fail before creating state", err)
		}
	}
}

func TestInboxCLIScanOnceUsesPerFileCheckpoints(t *testing.T) {
	isolateConnectionEnvironment(t)
	root := t.TempDir()
	incoming := filepath.Join(root, "incoming")
	spool := filepath.Join(root, "state")
	if err := os.Mkdir(incoming, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incoming, "one.jsonl"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client := filepath.Join(root, "client.sh")
	if err := os.WriteFile(client, []byte("#!/bin/sh\ncat >/dev/null\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := runArgs(t, "--input-dir", incoming, "--scan-once", "--spool", spool, "--client", client); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := 0
	for _, entry := range entries {
		if entry.IsDir() {
			b, err := os.ReadFile(filepath.Join(spool, entry.Name(), ".source"))
			if err != nil || !strings.Contains(string(b), `"offset":3`) {
				t.Fatal(err, string(b))
			}
			checkpoints++
		}
	}
	if checkpoints != 1 {
		t.Fatal("one source must retain one durable checkpoint", checkpoints)
	}
}

func TestCLIConnectionFlagsOverrideFileAndEnvironment(t *testing.T) {
	isolateConnectionEnvironment(t)
	root := t.TempDir()
	path := filepath.Join(root, "middleware.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"clickhouse":{"host":"file-host","port":9440,"user":"file_user","secure":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	client := filepath.Join(root, "client.sh")
	captured := filepath.Join(root, "args")
	if err := os.WriteFile(client, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\n' \"$@\" > \"$TEST_ARGS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input.jsonl")
	if err := os.WriteFile(input, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CYTHSEC_MIDDLEWARE_CONFIG", filepath.Join(root, "missing"))
	t.Setenv("CLICKHOUSE_PORT", "19000")
	t.Setenv("CLICKHOUSE_USER", "env_user")
	t.Setenv("TEST_ARGS", captured)
	if err := runArgs(t, "--config", path, "--input", input, "--spool", filepath.Join(root, "spool"), "--client", client, "--port", "21000", "--secure=false"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(captured)
	if err != nil {
		t.Fatal(err)
	}
	args := string(data)
	if !strings.Contains(args, "--host\nfile-host\n") || !strings.Contains(args, "--port\n21000\n") || !strings.Contains(args, "--user\nenv_user\n") || strings.Contains(args, "--secure") {
		t.Fatal("CLI/environment/file precedence mismatch")
	}
}
