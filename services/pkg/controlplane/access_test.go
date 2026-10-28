package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func accessFixture(t *testing.T, role string) (string, string, *Access) {
	t.Helper()
	credential := strings.Repeat("test-access-", 4)
	digest := sha256.Sum256([]byte(credential))
	data, _ := json.Marshal(map[string]any{"principals": []map[string]string{{"name": "test-reader", "role": role, "sha256": hex.EncodeToString(digest[:])}}})
	path := filepath.Join(t.TempDir(), "access.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, credential, a
}
func TestAccessBoundary(t *testing.T) {
	_, credential, policy := accessFixture(t, "viewer")
	var logs bytes.Buffer
	rt, err := NewRuntime(ServerConfig{Service: "telemetryd", MetricsEnabled: true, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Options{Service: "telemetryd", Access: policy, Logger: rt.Logger, Registry: rt.Registry}, func(mux *http.ServeMux) {
		Handle(mux, "POST /api/v1/analytics/imports", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	})
	for _, tc := range []struct {
		method, path, authorization string
		want                        int
	}{
		{"GET", "/healthz", "", 200}, {"HEAD", "/healthz", "", 200},
		{"GET", "/api/v1/version", "", 401}, {"GET", "/metrics", "", 401}, {"GET", "/api/v1/session", "", 401},
		{"GET", "/api/v1/session?access=" + credential, "", 401},
		{"GET", "/api/v1/session", "Basic " + credential, 401},
		{"GET", "/api/v1/session", "Bearer " + strings.Repeat("wrong", 10), 401},
		{"GET", "/api/v1/session", "Bearer " + credential, 200},
		{"POST", "/api/v1/analytics/imports", "Bearer " + credential, 403},
		{"POST", "/healthz", "", 401},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = "127.0.0.1:12000"
		if tc.authorization != "" {
			r.Header.Set("Authorization", tc.authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s: got %d want %d", tc.method, strings.Split(tc.path, "?")[0], w.Code, tc.want)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") == "" {
			t.Error("missing response guards")
		}
		if tc.want == 401 && w.Header().Get("WWW-Authenticate") == "" {
			t.Error("missing challenge")
		}
	}
	if strings.Contains(logs.String(), credential) {
		t.Fatal("credential leaked to logs")
	}
	r := httptest.NewRequest("GET", "/api/v1/session", nil)
	r.RemoteAddr = "127.0.0.1:12000"
	r.Header.Add("Authorization", "Bearer "+credential)
	r.Header.Add("Authorization", "Bearer "+credential)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate authorization accepted")
	}
	for _, role := range []string{"operator", "admin"} {
		_, value, p := accessFixture(t, role)
		for _, service := range []string{"routerd", "telemetryd"} {
			r := httptest.NewRequest("POST", "/api/v1/analytics/imports", nil)
			r.RemoteAddr = "127.0.0.1:12000"
			r.Header.Set("Authorization", "Bearer "+value)
			called := false
			guarded := p.middleware(service)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			guarded.ServeHTTP(httptest.NewRecorder(), r)
			if called != (service == "telemetryd") {
				t.Fatal("write capability crossed service boundary")
			}
		}
	}
}
func TestAccessInvalidPolicyFailsClosed(t *testing.T) {
	path, _, _ := accessFixture(t, "viewer")
	original, _ := os.ReadFile(path)
	for _, bad := range []string{`{}`, `{"principals":[]}`, `{"principals":[{"name":"a","role":"owner","sha256":"bad"}]}`, string(original) + " {}", strings.Replace(string(original), `"viewer"`, `"invalid"`, 1)} {
		os.WriteFile(path, []byte(bad), 0600)
		if _, err := LoadAccess(path); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	os.WriteFile(path, original, 0600)
	os.Chmod(path, 0644)
	if _, err := LoadAccess(path); err == nil {
		t.Fatal("non-private policy accepted")
	}
	if _, err := NewRuntime(ServerConfig{AccessFile: filepath.Join(t.TempDir(), "missing")}, nil); err == nil {
		t.Fatal("missing policy silently disabled authentication")
	}
}

func TestAccessTransportAndStartupPolicy(t *testing.T) {
	path, credential, _ := accessFixture(t, "viewer")
	runtime, err := NewRuntime(ServerConfig{Service: "routerd", AccessFile: path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/session", nil)
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.RemoteAddr = "192.0.2.1:12000"
	w := httptest.NewRecorder()
	runtime.Handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted forwarded headers bypass transport guard")
	}
	r.RemoteAddr = "127.0.0.1:12000"
	w = httptest.NewRecorder()
	runtime.Handler.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":true`) || strings.Contains(w.Body.String(), credential) {
		t.Fatal("startup policy is not protecting real runtime")
	}
}

func TestUnprotectedPublicListenerIsRejected(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080"} {
		if _, err := NewRuntime(ServerConfig{Addr: addr, RequireAccessForRemote: true}, nil); err == nil {
			t.Fatalf("unprotected listener allowed: %s", addr)
		}
	}
	if _, err := NewRuntime(ServerConfig{Addr: "127.0.0.1:8080", RequireAccessForRemote: true}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkConfigurationAccessIsNarrow(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "admin"} {
		_, value, policy := accessFixture(t, role)
		for _, tc := range []struct {
			service, method, path string
			allowed               bool
		}{
			{"routerd", "POST", "/api/v1/network/configuration/preview", true},
			{"routerd", "POST", "/api/v1/network/configuration/preflight", true},
			{"routerd", "POST", "/api/v1/network/configuration/native-validation", true},
			{"telemetryd", "POST", "/api/v1/network/configuration/native-validation", false},
			{"routerd", "PUT", "/api/v1/network/configuration/native-validation", false},
			{"routerd", "POST", "/api/v1/network/configuration/native-validation/execute", false},
			{"telemetryd", "POST", "/api/v1/network/configuration/preflight", false},
			{"routerd", "PUT", "/api/v1/network/configuration", role == "admin"},
			{"routerd", "DELETE", "/api/v1/network/configuration", false},
			{"routerd", "POST", "/api/v1/network/configuration/apply", false},
			{"telemetryd", "PUT", "/api/v1/network/configuration", false},
		} {
			called := false
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.RemoteAddr = "127.0.0.1:12000"
			r.Header.Set("Authorization", "Bearer "+value)
			policy.middleware(tc.service)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if IdentityFromContext(r.Context()).Role != role {
					t.Error("identity missing")
				}
			})).ServeHTTP(httptest.NewRecorder(), r)
			if called != tc.allowed {
				t.Fatalf("%s %s %s role=%s allowed=%v", tc.service, tc.method, tc.path, role, called)
			}
		}
	}
}
