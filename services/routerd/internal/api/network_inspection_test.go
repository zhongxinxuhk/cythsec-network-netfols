package api

import (
	"context"
	"cythsec/services/routerd/internal/networkcfg"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPersistentInspectionValidatesQueryBeforeReading(t *testing.T) {
	calls := 0
	server := NewServer(ServerOptions{NetworkInspect: func(_ context.Context, backend string) (networkcfg.PersistentInspection, error) {
		calls++
		return networkcfg.PersistentInspection{Backend: backend, Status: "unsupported", Sources: []networkcfg.ConfigSource{}, Profiles: []networkcfg.PersistentProfile{}}, nil
	}})
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"backend":"netplan","root":"/etc"}`, 400},
		{`{"backend":"../../etc"}`, 400},
		{`{"backend":"netplan","command":"apply"}`, 400},
		{`{"backend":"netplan"} {}`, 400},
		{`{"backend":"netplan"}`, 200},
	} {
		r := httptest.NewRequest("POST", "/api/v1/network/configuration/persistent-inspection", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(w.Code, w.Body.String())
		}
		if tc.status == 200 {
			var result struct {
				Data networkcfg.PersistentInspection
			}
			if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Data.CanApply || result.Data.Status != "unsupported" {
				t.Fatal("unsupported became writable success")
			}
		}
	}
	if calls != 1 {
		t.Fatal("invalid query reached source files", calls)
	}
}
func TestPersistentInspectionBusyDoesNotReturnEmptyProfiles(t *testing.T) {
	server := NewServer(ServerOptions{NetworkInspect: func(context.Context, string) (networkcfg.PersistentInspection, error) {
		return networkcfg.PersistentInspection{}, networkcfg.ErrObservationBusy
	}})
	r := httptest.NewRequest("POST", "/api/v1/network/configuration/persistent-inspection", strings.NewReader(`{"backend":"netplan"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatal(w.Code, w.Body.String())
	}
}
