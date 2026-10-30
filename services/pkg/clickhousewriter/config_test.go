package clickhousewriter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func configEnvironment(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}

func TestConnectionFileEnvironmentAndSecretPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "middleware.json")
	secret := "private-" + t.Name()
	if err := os.WriteFile(filepath.Join(dir, "credential"), []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"clickhouse":{"host":"file-host","port":9440,"user":"file_user","database":"file_db","table":"file_table","secure":true,"timeout":"3s","password_file":"credential"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadClientConfig(path, configEnvironment(nil))
	if err != nil || c.Host != "file-host" || c.Port != 9440 || !c.Secure || c.Timeout != 3*time.Second || c.credential == nil || *c.credential != secret {
		t.Fatal("file configuration did not resolve", err)
	}
	values := map[string]string{"CLICKHOUSE_HOST": "env-host", "CLICKHOUSE_PORT": "19000", "CLICKHOUSE_USER": "env_user", "CLICKHOUSE_DATABASE": "env_db", "CLICKHOUSE_TABLE": "env_table", "CLICKHOUSE_SECURE": "false", "CLICKHOUSE_TIMEOUT": "2s", "CLICKHOUSE_CLIENT": "other-client", "CLICKHOUSE_PASSWORD": ""}
	c, err = loadClientConfig(path, configEnvironment(values))
	if err != nil || c.Validate() != nil || c.Host != "env-host" || c.Port != 19000 || c.User != "env_user" || c.Database != "env_db" || c.Table != "env_table" || c.Secure || c.Timeout != 2*time.Second || c.Binary != "other-client" || *c.credential != "" {
		t.Fatal("environment override did not resolve", err)
	}
	values["CLICKHOUSE_PASSWORD_FILE"] = filepath.Join(dir, "credential")
	if _, err := loadClientConfig(path, configEnvironment(values)); err == nil {
		t.Fatal("ambiguous environment password sources accepted")
	}
	delete(values, "CLICKHOUSE_PASSWORD")
	c, err = loadClientConfig(path, configEnvironment(values))
	if err != nil || *c.credential != secret {
		t.Fatal("environment secret file not applied", err)
	}
}

func TestInvalidConnectionConfigurationFailsWithoutValues(t *testing.T) {
	for key, value := range map[string]string{"CLICKHOUSE_PORT": "not-a-port", "CLICKHOUSE_SECURE": "unknown-bool", "CLICKHOUSE_TIMEOUT": "invalid-duration"} {
		_, err := loadClientConfig("", configEnvironment(map[string]string{key: value}))
		if err == nil || strings.Contains(err.Error(), value) {
			t.Fatal("invalid configuration not rejected safely", key)
		}
	}
	for _, body := range []string{`{"version":2}`, `{"version":1}`, `{"version":1,"clickhouse":null}`, `{"version":1,"clickhouse":{"password":"literal-value"}}`, `{"version":1} {}`, `null`, `{"version":1,"clickhouse":{"timeout":"bad-value"}}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadClientConfig(path, configEnvironment(nil)); err == nil {
			t.Fatal("invalid file accepted")
		}
	}
	if _, err := loadClientConfig(filepath.Join(t.TempDir(), "missing"), configEnvironment(nil)); err == nil {
		t.Fatal("explicit missing config silently fell back")
	}
	c, err := loadClientConfig("", configEnvironment(map[string]string{"CLICKHOUSE_PORT": "0"}))
	if err != nil || c.Validate() == nil {
		t.Fatal("invalid final connection range accepted", err)
	}
}

func TestClientPasswordNeverEntersArgumentsMetadataOrErrors(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Repeat("sentinel-"+t.Name(), 100)
	secretPath := filepath.Join(dir, "credential")
	if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "client.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$@\" > \"$TEST_ARGS\"\nprintf '%s' \"$CLICKHOUSE_PASSWORD\" > \"$TEST_SECRET\"\nprintf 'native error: %s' \"$CLICKHOUSE_PASSWORD\" >&2\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	argsPath, captured := filepath.Join(dir, "args"), filepath.Join(dir, "captured")
	t.Setenv("TEST_ARGS", argsPath)
	t.Setenv("TEST_SECRET", captured)
	t.Setenv("CLICKHOUSE_PASSWORD", "ambient-value")
	c, err := loadClientConfig("", configEnvironment(map[string]string{"CLICKHOUSE_CLIENT": script, "CLICKHOUSE_PASSWORD_FILE": secretPath}))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Send(context.Background(), "stable-id", []byte("{}\n"))
	if err == nil || strings.Contains(err.Error(), secret[:32]) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatal("native error leaked credential or was lost")
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(captured)
	if err != nil || string(value) != secret {
		t.Fatal("child environment credential did not resolve", err)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), secret) || strings.Contains(string(args), "--password") || strings.Contains(string(encoded), secret) || strings.Contains(c.Target(), secret) {
		t.Fatal("credential escaped into arguments or persistent target metadata")
	}
}

func TestConnectionURIWithEmbeddedCredentialsRejectedBeforeQueueBinding(t *testing.T) {
	c := DefaultClient()
	c.Host = "clickhouse://user:credential@host"
	if c.Validate() == nil {
		t.Fatal("connection URI accepted as host")
	}
}
