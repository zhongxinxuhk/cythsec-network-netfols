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

func TestInboxCLIRejectsConflictingSourceOwnership(t *testing.T) {
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
