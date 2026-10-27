package api

import (
	"crypto/sha256"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/networkcfg"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const networkBody = `{"backend":"netplan","interfaces":[{"id":"lan","device":"eth0","mtu":1500,"addresses":["192.0.2.10/24"],"dns":["192.0.2.53"],"search":[],"routes":[{"destination":"0.0.0.0/0","gateway":"192.0.2.1","metric":100}]}]}`

func TestNetworkConfigurationAPI(t *testing.T) {
	store, err := networkcfg.Open(filepath.Join(t.TempDir(), "network"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, role := range []string{"viewer", "operator", "admin"} {
		credential := strings.Repeat("test-network-", 4)
		digest := sha256.Sum256([]byte(credential))
		raw, _ := json.Marshal(map[string]any{"principals": []map[string]string{{"name": "test-admin", "role": role, "sha256": hex.EncodeToString(digest[:])}}})
		path := filepath.Join(t.TempDir(), "policy.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		policy, err := controlplane.LoadAccess(path)
		if err != nil {
			t.Fatal(err)
		}
		server := NewServer(ServerOptions{Access: policy, NetworkConfig: store})
		call := func(method, path, body, etag string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			r.RemoteAddr = "127.0.0.1:12000"
			r.Header.Set("Authorization", "Bearer "+credential)
			r.Header.Set("Content-Type", "application/json")
			if etag != "" {
				r.Header.Set("If-Match", etag)
			}
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			return w
		}
		if w := call("GET", "/api/v1/network/configuration", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"can_apply":false`) {
			t.Fatal(w.Code, w.Body.String())
		}
		if w := call("POST", "/api/v1/network/configuration/preview", networkBody, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "validated_preview") {
			t.Fatal(w.Code, w.Body.String())
		}
		want := 403
		if role == "admin" {
			want = 200
		}
		if w := call("PUT", "/api/v1/network/configuration", networkBody, `"0"`); w.Code != want {
			t.Fatal(role, w.Code, w.Body.String())
		}
		if role == "admin" {
			if w := call("PUT", "/api/v1/network/configuration", networkBody, `"0"`); w.Code != 412 {
				t.Fatal("stale version accepted")
			}
			if w := call("PUT", "/api/v1/network/configuration", networkBody, ""); w.Code != 428 {
				t.Fatal("unconditional write accepted")
			}
		}
		for _, body := range []string{strings.Replace(networkBody, `"backend"`, `"command":"reboot","backend"`, 1), networkBody + " {}", strings.Repeat(" ", 131072) + networkBody} {
			if w := call("POST", "/api/v1/network/configuration/preview", body, ""); w.Code != 400 {
				t.Fatal("invalid body accepted", w.Code)
			}
		}
	}
}
func TestNetworkConfigurationAnonymousCannotSave(t *testing.T) {
	store, err := networkcfg.Open(filepath.Join(t.TempDir(), "network"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, s := range []*networkcfg.Store{nil, store} {
		server := NewServer(ServerOptions{NetworkConfig: s})
		r := httptest.NewRequest("PUT", "/api/v1/network/configuration", strings.NewReader(networkBody))
		r.Header.Set("If-Match", `"0"`)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != 403 || store.Read().Revision != 0 {
			t.Fatal("anonymous configuration mutation")
		}
	}
}

func TestNetworkVersionHeadersAvailableToAllowedOrigin(t *testing.T) {
	s := NewServer(ServerOptions{})
	r := httptest.NewRequest("OPTIONS", "/api/v1/network/configuration", nil)
	r.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "If-Match") || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "ETag") {
		t.Fatal("network version headers hidden by CORS")
	}
}
