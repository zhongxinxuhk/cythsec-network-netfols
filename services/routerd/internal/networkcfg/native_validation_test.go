package networkcfg

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validatorFixture() *NativeValidator {
	return &NativeValidator{"linux", func() int { return 1000 }, func(tool string) (string, error) { return "/usr/bin/" + tool, nil }, func(_ context.Context, path string, args []string, input, dir string) ([]byte, error) {
		if filepath.Base(path) == "systemctl" {
			return []byte("running\n"), nil
		}
		if reflect.DeepEqual(args, []string{"--version"}) {
			return []byte("nmcli tool, version 1.50.0\n"), nil
		}
		if reflect.DeepEqual(args, []string{"generate", "--help"}) {
			return []byte("--root-dir ROOT --mapping MAPPING"), nil
		}
		return []byte("parsed"), nil
	}, make(chan struct{}, 1)}
}

func TestNativeValidatorGuardsBeforeCommands(t *testing.T) {
	for _, tc := range []struct {
		platform     string
		uid          int
		status, code string
	}{{"darwin", 501, "unsupported", "unsupported_platform"}, {"linux", 0, "unavailable", "unprivileged_worker_required"}} {
		v := validatorFixture()
		v.platform = tc.platform
		v.euid = func() int { return tc.uid }
		v.find = func(string) (string, error) { t.Fatal("guard executed native discovery"); return "", nil }
		r, err := v.Validate(context.Background(), fixture())
		if err != nil || r.Status != tc.status || r.Checks[0].Code != tc.code || r.CanApply || r.DraftDigest != Digest(fixture()) || r.CheckedAt.IsZero() {
			t.Fatal(r, err)
		}
	}
	v := validatorFixture()
	v.find = func(string) (string, error) { t.Fatal("invalid draft reached native tool"); return "", nil }
	if _, err := v.Validate(context.Background(), Config{Backend: "shell"}); err == nil {
		t.Fatal("invalid draft accepted")
	}
}

func TestNativeValidatorUsesOnlyIsolatedParserCommands(t *testing.T) {
	for _, backend := range []string{"networkmanager", "netplan", "openwrt"} {
		t.Run(backend, func(t *testing.T) {
			c := fixture()
			c.Backend = backend
			v := validatorFixture()
			run := v.run
			workspace := ""
			parserCalls := 0
			v.run = func(ctx context.Context, path string, args []string, input, dir string) ([]byte, error) {
				workspace = dir
				st, err := os.Stat(dir)
				if err != nil || st.Mode().Perm() != 0700 {
					t.Fatal("workspace is not private", err)
				}
				switch {
				case backend == "networkmanager" && len(args) > 0 && args[0] == "--offline":
					parserCalls++
					if !reflect.DeepEqual(args, []string{"--offline", "connection", "modify", "connection.autoconnect", "yes"}) || !strings.Contains(input, "[connection]") {
						t.Fatal("online or arbitrary command", args)
					}
				case backend == "netplan" && len(args) > 2:
					parserCalls++
					if !reflect.DeepEqual(args, []string{"generate", "--root-dir", dir, "--mapping", c.Interfaces[0].Device}) {
						t.Fatal(args)
					}
					file := filepath.Join(dir, "etc", "netplan", "90-cythsec.yaml")
					if st, e := os.Stat(file); e != nil || st.Mode().Perm() != 0600 {
						t.Fatal("config not private", e)
					}
				case backend == "openwrt":
					parserCalls++
					if !reflect.DeepEqual(args, []string{"-c", dir, "-P", filepath.Join(dir, "delta"), "-s", "export", filepath.Join(dir, "network")}) {
						t.Fatal("UCI must export only the absolute private file", args)
					}
				}
				return run(ctx, path, args, input, dir)
			}
			r, err := v.Validate(context.Background(), c)
			if err != nil || r.Status != "passed" || r.CanApply || parserCalls != 1 {
				t.Fatal(r, err, parserCalls)
			}
			if _, err = os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("temporary workspace retained", err)
			}
		})
	}
}

func TestNativeValidatorDoesNotTurnIncompleteIntoPass(t *testing.T) {
	for _, tc := range []struct{ name, backend, status, code string }{
		{"old_nm", "networkmanager", "unsupported", "offline_unavailable"},
		{"boot", "netplan", "unavailable", "boot_state_unavailable"},
		{"help", "netplan", "unsupported", "isolated_parser_unavailable"},
		{"empty", "openwrt", "unavailable", "execution_incomplete"},
		{"deadline", "openwrt", "unavailable", "execution_incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := validatorFixture()
			run := v.run
			v.run = func(ctx context.Context, path string, args []string, input, dir string) ([]byte, error) {
				if tc.name == "old_nm" {
					return []byte("nmcli tool, version 1.38.0"), nil
				}
				if tc.name == "boot" && filepath.Base(path) == "systemctl" {
					return []byte("initializing"), nil
				}
				if tc.name == "help" && reflect.DeepEqual(args, []string{"generate", "--help"}) {
					return []byte("generate"), nil
				}
				if tc.name == "empty" {
					return nil, nil
				}
				if tc.name == "deadline" {
					return nil, context.DeadlineExceeded
				}
				return run(ctx, path, args, input, dir)
			}
			c := fixture()
			c.Backend = tc.backend
			r, err := v.Validate(context.Background(), c)
			if err != nil || r.Status != tc.status || r.Checks[0].Code != tc.code || r.CanApply {
				t.Fatal(r, err)
			}
		})
	}
}

func TestNativeValidatorSerializesWork(t *testing.T) {
	v := validatorFixture()
	entered, release := make(chan struct{}), make(chan struct{})
	v.find = func(string) (string, error) { close(entered); <-release; return "", os.ErrNotExist }
	done := make(chan struct{})
	go func() { defer close(done); v.Validate(context.Background(), fixture()) }()
	<-entered
	if _, err := v.Validate(context.Background(), fixture()); !errors.Is(err, ErrObservationBusy) {
		t.Fatal("parallel parsing accepted")
	}
	close(release)
	<-done
}

func TestNativeCommandUsesPrivateEnvironmentAndInput(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	args := []string{"-test.run=TestNativeCommandHelper", "--", "cythsec-native-test"}
	raw, err := captureProbeCommand(context.Background(), path, args, "profile", dir)
	if err != nil || string(raw) != "profile" {
		t.Fatal("stdin or environment isolation failed", string(raw), err)
	}
	_, err = captureProbeCommand(context.Background(), path, append(args, "reject"), "", dir)
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 2 {
		t.Fatal("native rejection not preserved", err)
	}
	v := validatorFixture()
	rejection := err
	v.run = func(context.Context, string, []string, string, string) ([]byte, error) { return nil, rejection }
	c := fixture()
	c.Backend = "openwrt"
	r, err := v.Validate(context.Background(), c)
	if err != nil || r.Status != "rejected" || r.Checks[0].Code != "parser_rejected" || r.CanApply {
		t.Fatal("native rejection became a successful check", r, err)
	}
}
func TestNativeCommandHelper(t *testing.T) {
	args := strings.Join(os.Args, " ")
	if !strings.Contains(args, "-- cythsec-native-test") {
		return
	}
	if strings.HasSuffix(args, " reject") {
		os.Exit(2)
	}
	wd, err := os.Getwd()
	home, homeErr := filepath.EvalSymlinks(os.Getenv("HOME"))
	tmp, tmpErr := filepath.EvalSymlinks(os.Getenv("TMPDIR"))
	if err != nil || homeErr != nil || tmpErr != nil || home != wd || tmp != wd || os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		os.Exit(3)
	}
	io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}
