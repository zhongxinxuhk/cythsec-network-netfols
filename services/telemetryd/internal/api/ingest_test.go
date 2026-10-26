package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"cythsec/services/telemetryd/internal/aggregate"
)

func TestIngestAcceptsDurablyWithoutClaimingArchived(t *testing.T) {
	root := t.TempDir()
	archive, err := aggregate.Open(filepath.Join(root, "history"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	queue, err := aggregate.Open(filepath.Join(root, "queue"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	worker := aggregate.NewWorker(archive, queue)
	h := NewServer(ServerOptions{Aggregates: archive, Ingest: worker, Logger: discardLogger()})
	raw, err := os.ReadFile("../aggregate/testdata/cohort.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/analytics/ingest"
	for n := 0; n < 2; n++ {
		rec := local(h, "POST", path, raw)
		var response struct {
			Data struct {
				Durable   bool   `json:"durable"`
				Stage     string `json:"acknowledged_stage"`
				Duplicate bool   `json:"duplicate"`
			} `json:"data"`
		}
		if rec.Code != 202 || json.Unmarshal(rec.Body.Bytes(), &response) != nil || !response.Data.Durable || response.Data.Stage != "queue" || response.Data.Duplicate != (n > 0) {
			t.Fatal(rec.Code, rec.Body)
		}
	}
	if len(archive.List()) != 0 || len(queue.List()) != 1 {
		t.Fatal("queue acknowledgement mistaken for archive commit")
	}
	rec := local(h, "GET", path, nil)
	var status struct {
		Data aggregate.IngestStatus `json:"data"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &status) != nil || status.Data.PendingBatches != 1 || !status.Data.Enabled {
		t.Fatal(rec.Body)
	}
	if rec := archiveRequest(h, "POST", path, raw, "198.51.100.1:12", "application/x-ndjson"); rec.Code != http.StatusForbidden {
		t.Fatal("nonlocal queue accepted")
	}
	if rec := local(h, "POST", path, []byte("{}")); rec.Code != 400 {
		t.Fatal(rec.Code)
	}
}
func TestIngestDisabledDoesNotPretendToHaveAcceptedData(t *testing.T) {
	s, err := aggregate.Open(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := NewServer(ServerOptions{Aggregates: s, Logger: discardLogger()})
	if rec := local(h, "POST", "/api/v1/analytics/ingest", []byte("{}")); rec.Code != 503 {
		t.Fatal(rec.Code)
	}
	rec := local(h, "GET", "/api/v1/analytics/ingest", nil)
	var reply struct {
		Data aggregate.IngestStatus `json:"data"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &reply) != nil || reply.Data.Enabled || reply.Data.State != "disabled" {
		t.Fatal(rec.Body)
	}
}
