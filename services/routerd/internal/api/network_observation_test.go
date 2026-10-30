package api

import (
	"context"
	"cythsec/services/routerd/internal/networkcfg"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkObservationAndPreflightRoutes(t *testing.T) {
	calls := 0
	observer := func(context.Context) (networkcfg.Observation, error) {
		calls++
		return networkcfg.Observation{ID: strings.Repeat("a", 64), Platform: "linux", InventoryAvailable: true, Status: "partial", Interfaces: []networkcfg.ObservedInterface{}, Managers: []networkcfg.ManagerObservation{}, Warnings: []string{}}, nil
	}
	server := NewServer(ServerOptions{NetworkObserve: observer})
	r := httptest.NewRequest("GET", "/api/v1/network/configuration/observation", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != 200 || calls != 1 {
		t.Fatal(w.Code, calls)
	}
	r = httptest.NewRequest("POST", "/api/v1/network/configuration/preflight", strings.NewReader(networkBody))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	server.ServeHTTP(w, r)
	var response struct{ Data networkcfg.Preflight }
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || w.Code != 200 || calls != 2 || response.Data.CanApply || response.Data.Status != "blocked" || len(response.Data.Differences) != 5 {
		t.Fatal(w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "/api/v1/network/configuration/preflight", strings.NewReader(`{"backend":"shell","interfaces":[]}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != 400 || calls != 2 {
		t.Fatal("invalid request started native probes")
	}
}
func TestNetworkObservationBusyIsNotEmptySuccess(t *testing.T) {
	server := NewServer(ServerOptions{NetworkObserve: func(context.Context) (networkcfg.Observation, error) {
		return networkcfg.Observation{}, networkcfg.ErrObservationBusy
	}})
	r := httptest.NewRequest("GET", "/api/v1/network/configuration/observation", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("busy capture became success")
	}
}
