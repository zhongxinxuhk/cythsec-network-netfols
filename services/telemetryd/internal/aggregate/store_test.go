package aggregate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cohort.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func openTest(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestDurableRestartDedupAndTimePagination(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	s := openTest(t, dir)
	data := fixture(t)
	m, dup, err := s.Put(data)
	if err != nil || dup || m.Windows != 2 {
		t.Fatalf("put: %+v %v %v", m, dup, err)
	}
	var padded bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var v any
		if json.Unmarshal(line, &v) != nil {
			t.Fatal("fixture")
		}
		b, _ := json.MarshalIndent(v, "", " ")
		var compact bytes.Buffer
		_ = json.Compact(&compact, b)
		padded.WriteString(" " + compact.String() + " \n")
	}
	again, dup, err := s.Put(padded.Bytes())
	if err != nil || !dup || again.ID != m.ID || len(s.List()) != 1 {
		t.Fatal("canonical retry must not double count", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, dir)
	page, err := s.Query(m.ID, 60, 120, 0, 1)
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Start != 60 {
		t.Fatal("restart/range", err, page)
	}
	page, err = s.Query(m.ID, 0, 120, 1, 1)
	if err != nil || page.Total != 2 || page.Items[0].Start != 60 {
		t.Fatal("pagination", err)
	}
	page, err = s.Query(m.ID, 0, 120, 100, 1)
	if err != nil || page.Items == nil || len(page.Items) != 0 {
		t.Fatal("empty page must be []", err)
	}
	info, _ := os.Stat(filepath.Join(dir, m.ID+".jsonl"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("private file mode")
	}
}
func TestConcurrentRetriesAndSingleWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	s := openTest(t, dir)
	if other, err := Open(dir); err == nil {
		other.Close()
		t.Fatal("second writer accepted")
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Put(fixture(t)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(s.List()) != 1 {
		t.Fatal("retry duplicated batch")
	}
}
func TestQuotaWriteFailureAndUncommittedRecovery(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "archive")
	s := openTest(t, dir)
	s.maxBytes = 1
	if _, _, err := s.Put(fixture(t)); !errors.Is(err, ErrFull) || len(s.List()) != 0 {
		t.Fatal("capacity must fail before commit", err)
	}
	s.maxBytes = MaxStoreBytes
	if err := os.Rename(dir, dir+"-moved"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put(fixture(t)); err == nil {
		t.Fatal("write failure acknowledged")
	}
	if err := os.Rename(dir+"-moved", dir); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.WriteFile(filepath.Join(dir, ".pending-interrupted"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, dir)
	if len(s.List()) != 0 {
		t.Fatal("uncommitted file became history")
	}
	if _, err := os.Stat(filepath.Join(dir, ".pending-interrupted")); !os.IsNotExist(err) {
		t.Fatal("orphan was not removed")
	}
}
func TestCorruptCommittedFileFailsReadAndStartup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	s := openTest(t, dir)
	m, _, err := s.Put(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, m.ID+".jsonl"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Query(m.ID, 0, 120, 0, 100); err == nil {
		t.Fatal("corruption returned as history")
	}
	s.Close()
	if other, err := Open(dir); err == nil {
		other.Close()
		t.Fatal("corrupt archive silently skipped")
	}
}
func TestPartialAndUnknownRemainDistinctFromZeroLoss(t *testing.T) {
	b, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	b.Status.AnalysisComplete = false
	s := openTest(t, filepath.Join(t.TempDir(), "archive"))
	m, _, err := s.Put(canonical(b))
	if err != nil {
		t.Fatal(err)
	}
	if m.Status.AnalysisComplete || m.Status.Loss != "unknown" || m.Status.Consistent != nil {
		t.Fatal("status rewritten")
	}
	b.Windows[0].Statistics = nil
	b.Windows[0].Suppressed = true
	b.Windows[0].Reason = "insufficient_sampled_flow_cohort"
	b.Status.Published--
	b.Status.Suppressed++
	m, _, err = s.Put(canonical(b))
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Query(m.ID, 0, 120, 0, 100)
	if err != nil || page.Items[0].Statistics != nil {
		t.Fatal("suppression changed to zero", err)
	}
}
func TestStrictSchemaRejectsRawFieldsMissingNullAndUnsafeValues(t *testing.T) {
	data := fixture(t)
	mutations := []struct{ name, old, new string }{
		{"identifier", "\"records\":20", "\"src_ip\":\"sensitive-marker\",\"records\":20"},
		{"missing scalar", "\"late_records\":0,", ""},
		{"null scalar", "\"records\":20", "\"records\":null"},
		{"unsafe JS integer", "\"records\":20", "\"records\":9007199254740992"},
		{"equation", "\"records\":20", "\"records\":21"},
		{"small cohort", "\"contributing_sampled_flows\":20", "\"contributing_sampled_flows\":1"},
		{"overlap", "\"window_start_seconds\":60", "\"window_start_seconds\":0"},
		{"capacity false green", "\"capacity_rejected_packets\":0", "\"capacity_rejected_packets\":1"},
		{"trailer count", "\"published_windows\":2", "\"published_windows\":1"},
		{"source uncertainty", "\"capture_loss_status\":\"unknown\"", "\"capture_loss_status\":\"declared_zero\""},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			if !bytes.Contains(data, []byte(m.old)) {
				t.Fatal("injection missed")
			}
			bad := bytes.Replace(data, []byte(m.old), []byte(m.new), 1)
			if _, err := Parse(bad); err == nil {
				t.Fatal("invalid data accepted")
			}
		})
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for _, bad := range [][]byte{nil, bytes.Join(lines[:2], []byte("\n")), append(data, lines[0]...), []byte(strings.Repeat("x", MaxBatchBytes+1))} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("missing/extra/large record accepted")
		}
	}
}
func TestHistogramCohortAndSumAreValidated(t *testing.T) {
	b, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	s := b.Windows[0].Statistics
	s.UDP = 0
	s.TCP = 20
	bounds := []uint64{1, 5, 10, 25, 50, 100, 250, 1000, 30000}
	q := &Quality{TCPFlows: 20, Judged: 20}
	for _, v := range bounds {
		v := v
		q.DelayBounds = append(q.DelayBounds, &v)
	}
	q.DelayBounds = append(q.DelayBounds, nil)
	samples := uint64(20)
	hist := []uint64{20, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	q.DelaySamples = &samples
	q.DelayHistogram = &hist
	s.Quality = q
	if _, err := Parse(canonical(b)); err != nil {
		t.Fatal(err)
	}
	hist[0] = 19
	if _, err := Parse(canonical(b)); err == nil {
		t.Fatal("histogram sum mismatch accepted")
	}
	hist[0] = 1
	samples = 1
	if _, err := Parse(canonical(b)); err == nil {
		t.Fatal("single-flow histogram published")
	}
}
