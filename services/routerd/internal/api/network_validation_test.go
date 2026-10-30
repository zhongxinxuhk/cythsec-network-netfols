package api

import (
	"context"
	"cythsec/services/routerd/internal/networkcfg"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeValidationRouteValidatesBeforeExecution(t *testing.T) {
	calls := 0
	server := NewServer(ServerOptions{NetworkValidate: func(_ context.Context, c networkcfg.Config) (networkcfg.NativeValidation, error) {
		calls++
		return networkcfg.NativeValidation{DraftDigest: networkcfg.Digest(c), Backend: c.Backend, Status: "unsupported", Checks: []networkcfg.NativeCheck{}}, nil
	}})
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"backend":"shell","interfaces":[]}`, 400},
		{strings.TrimSuffix(networkBody, "}") + `,"command":"apply"}`, 400},
		{networkBody, 200},
	} {
		r := httptest.NewRequest("POST", "/api/v1/network/configuration/native-validation", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal(w.Code, w.Body.String())
		}
		if tc.want == 200 {
			var data struct{ Data networkcfg.NativeValidation }
			if json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Data.CanApply || data.Data.Status != "unsupported" {
				t.Fatal("native unavailability became apply permission")
			}
		}
	}
	if calls != 1 {
		t.Fatal("invalid input started native commands", calls)
	}
}
func TestNativeValidationBusyPreservesFailure(t *testing.T) {
	server := NewServer(ServerOptions{NetworkValidate: func(context.Context, networkcfg.Config) (networkcfg.NativeValidation, error) {
		return networkcfg.NativeValidation{}, networkcfg.ErrObservationBusy
	}})
	r := httptest.NewRequest("POST", "/api/v1/network/configuration/native-validation", strings.NewReader(networkBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatal(w.Code, w.Body.String())
	}
}
