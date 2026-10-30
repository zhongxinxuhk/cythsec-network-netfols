package api

import (
	"bytes"
	"crypto/sha256"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/telemetryd/internal/aggregate"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedAggregateImport(t *testing.T) {
	archive, err := aggregate.Open(filepath.Join(t.TempDir(), "archive"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	data, err := os.ReadFile("../aggregate/testdata/cohort.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("local-test-", 5)
	digest := sha256.Sum256([]byte(credential))
	for _, role := range []string{"viewer", "operator"} {
		raw, _ := json.Marshal(map[string]any{"principals": []map[string]string{{"name": "ingest-test", "role": role, "sha256": hex.EncodeToString(digest[:])}}})
		file := filepath.Join(t.TempDir(), "access.json")
		os.WriteFile(file, raw, 0600)
		policy, err := controlplane.LoadAccess(file)
		if err != nil {
			t.Fatal(err)
		}
		h := NewServer(ServerOptions{Access: policy, Aggregates: archive, Logger: discardLogger()})
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest("POST", "/api/v1/analytics/imports", bytes.NewReader(data))
			r.RemoteAddr = "127.0.0.1:12000"
			r.Header.Set("Content-Type", "application/x-ndjson")
			if authenticated {
				r.Header.Set("Authorization", "Bearer "+credential)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 401
			if authenticated {
				want = 403
				if role == "operator" {
					want = 201
				}
			}
			if w.Code != want {
				t.Fatalf("%s authenticated=%v got %d want %d", role, authenticated, w.Code, want)
			}
		}
	}
}
