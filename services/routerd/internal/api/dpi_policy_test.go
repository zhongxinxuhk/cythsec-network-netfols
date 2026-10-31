package api

import (
	"crypto/sha256"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/dpipolicy"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dpiPolicyBody = `{"schema_version":1,"enabled":true,"intensity":"deep","inspect_bytes":null,"modules":{"tls":false,"smtp":true},"tls_decrypt":{"enabled":true,"keylog_file":"/var/lib/cythsec/tls.keys"}}`

func newDPITestServer(t *testing.T, role string) (*httptest.Server, *dpipolicy.Store, string) {
	t.Helper()
	store, err := dpipolicy.Open(filepath.Join(t.TempDir(), "dpi"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	credential := strings.Repeat("test-dpi-policy-", 4)
	digest := sha256.Sum256([]byte(credential))
	raw, _ := json.Marshal(map[string]any{"principals": []map[string]string{{"name": "test-admin", "role": role, "sha256": hex.EncodeToString(digest[:])}}})
	path := filepath.Join(t.TempDir(), "policy.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	access, err := controlplane.LoadAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(ServerOptions{Access: access, DPIPolicy: store})
	return httptest.NewServer(server), store, credential
}

func TestDPIPolicyAPIRequiresAdminAndVersion(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "admin"} {
		server, store, credential := newDPITestServer(t, role)
		call := func(method, path, body, etag string) *httptest.ResponseRecorder {
			request := httptest.NewRequest(method, path, strings.NewReader(body))
			request.RemoteAddr = "127.0.0.1:12000"
			request.Header.Set("Authorization", "Bearer "+credential)
			request.Header.Set("Content-Type", "application/json")
			if etag != "" {
				request.Header.Set("If-Match", etag)
			}
			w := httptest.NewRecorder()
			server.Config.Handler.ServeHTTP(w, request)
			return w
		}
		wantCanSave := "false"
		if role == "admin" {
			wantCanSave = "true"
		}
		if w := call("GET", "/api/v1/dpi/policy", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"can_save":`+wantCanSave) {
			t.Fatalf("%s GET: %d %s", role, w.Code, w.Body.String())
		}
		want := 403
		if role == "admin" {
			want = 200
		}
		if w := call("PUT", "/api/v1/dpi/policy", dpiPolicyBody, `"0"`); w.Code != want {
			t.Fatalf("%s PUT: %d %s", role, w.Code, w.Body.String())
		}
		if role == "admin" {
			if store.Read().Revision != 1 {
				t.Fatal("admin save did not persist")
			}
			if w := call("PUT", "/api/v1/dpi/policy", dpiPolicyBody, `"0"`); w.Code != 412 {
				t.Fatalf("stale revision accepted: %d", w.Code)
			}
			if w := call("PUT", "/api/v1/dpi/policy", dpiPolicyBody, ""); w.Code != 428 {
				t.Fatalf("unconditional save accepted: %d", w.Code)
			}
			for _, body := range []string{
				strings.Replace(dpiPolicyBody, `"tls":false`, `"typo":false`, 1),
				strings.Replace(dpiPolicyBody, `"deep"`, `"turbo"`, 1),
				dpiPolicyBody + " {}",
			} {
				if w := call("PUT", "/api/v1/dpi/policy", body, `"1"`); w.Code != 400 {
					t.Fatalf("invalid policy accepted: %d %s", w.Code, w.Body.String())
				}
			}
		}
		server.Close()
	}
}

func TestDPIPolicyAnonymousCannotSave(t *testing.T) {
	store, err := dpipolicy.Open(filepath.Join(t.TempDir(), "dpi"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(ServerOptions{DPIPolicy: store})
	request := httptest.NewRequest("PUT", "/api/v1/dpi/policy", strings.NewReader(dpiPolicyBody))
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, request)
	if w.Code != 403 || store.Read().Revision != 0 {
		t.Fatalf("anonymous mutation: %d", w.Code)
	}
}

func TestDPIModulesCatalogEndpoint(t *testing.T) {
	server := NewServer(ServerOptions{})
	request := httptest.NewRequest("GET", "/api/v1/dpi/modules", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"key":"tls"`, `"key":"http"`, `"availability":"implemented"`, `"catalog_ids":["T001","T002","T022"]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("catalog missing %s: %s", want, body)
		}
	}
}
