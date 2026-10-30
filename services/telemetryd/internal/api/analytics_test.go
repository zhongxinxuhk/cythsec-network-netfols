package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cythsec/services/telemetryd/internal/aggregate"
)

func archiveServer(t *testing.T) (http.Handler, []byte) {
	t.Helper()
	s, err := aggregate.Open(filepath.Join(t.TempDir(), "archive"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	data, err := os.ReadFile("../aggregate/testdata/cohort.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(ServerOptions{Aggregates: s, Logger: discardLogger()}), data
}
func archiveRequest(h http.Handler, method, path string, body []byte, remote, media string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = remote
	r.Header.Set("Content-Type", media)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func local(h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	return archiveRequest(h, method, path, body, "127.0.0.1:1234", "application/x-ndjson")
}
func TestAggregateAPIImportRetryQueryAndPaging(t *testing.T) {
	h, data := archiveServer(t)
	const root = "/api/v1/analytics/imports"
	rec := local(h, "POST", root, data)
	if rec.Code != 201 {
		t.Fatal(rec.Code, rec.Body)
	}
	var reply struct {
		Data struct {
			Import  aggregate.Import `json:"import"`
			Durable bool             `json:"durable"`
		} `json:"data"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &reply) != nil || !reply.Data.Durable {
		t.Fatal("durability acknowledgement")
	}
	if rec := local(h, "POST", root, data); rec.Code != 200 {
		t.Fatal("duplicate", rec.Code)
	}
	rec = local(h, "GET", root+"/"+reply.Data.Import.ID+"?from=60&to=120&limit=1", nil)
	var page struct {
		Data aggregate.Page `json:"data"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &page) != nil || rec.Code != 200 || page.Data.Total != 1 || page.Data.Items[0].Start != 60 {
		t.Fatal("range", rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache policy")
	}
	for _, q := range []string{"from=x", "from=120&to=60", "limit=101", "offset=1025", "from=0&from=1", "where=anything"} {
		if r := local(h, "GET", root+"/"+reply.Data.Import.ID+"?"+q, nil); r.Code != 400 {
			t.Fatal(q, r.Code)
		}
	}
	if r := local(h, "GET", root+"/unknown", nil); r.Code != 404 {
		t.Fatal(r.Code)
	}
	rec = local(h, "GET", root, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatal("list", rec.Body)
	}
}
func TestAggregateAPIBoundariesAndNoSensitiveEcho(t *testing.T) {
	h, data := archiveServer(t)
	const root = "/api/v1/analytics/imports"
	if r := archiveRequest(h, "GET", root, nil, "198.51.100.1:12", ""); r.Code != 403 {
		t.Fatal("nonlocal accepted", r.Code)
	}
	if r := archiveRequest(h, "POST", root, data, "127.0.0.1:12", "text/plain"); r.Code != 415 {
		t.Fatal(r.Code)
	}
	if r := local(h, "POST", root, bytes.Repeat([]byte("x"), aggregate.MaxBatchBytes+1)); r.Code != 413 {
		t.Fatal(r.Code)
	}
	bad := bytes.Replace(data, []byte(`"records":20`), []byte(`"private_domain":"sensitive-marker","records":20`), 1)
	rec := local(h, "POST", root, bad)
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "sensitive-marker") {
		t.Fatal("schema/echo", rec.Body)
	}
	h = NewServer(ServerOptions{Logger: discardLogger()})
	if r := local(h, "GET", root, nil); r.Code != 503 {
		t.Fatal("disabled store appeared empty", r.Code)
	}
}
