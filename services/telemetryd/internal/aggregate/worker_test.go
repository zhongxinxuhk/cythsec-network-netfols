package aggregate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func stepAt(w *Worker, now time.Time) bool { return w.step(func() time.Time { return now }) }
func workerStores(t *testing.T) (*Store, *Store) {
	t.Helper()
	root := t.TempDir()
	return openTest(t, filepath.Join(root, "history")), openTest(t, filepath.Join(root, "queue"))
}
func TestWorkerCommitThenAcknowledgeAndReplayAfterRestart(t *testing.T) {
	archive, queue := workerStores(t)
	raw := fixture(t)
	m, duplicate, err := queue.Put(raw)
	if err != nil || duplicate {
		t.Fatal(err)
	}
	// Simulate interruption after destination sync, before source acknowledgment.
	if _, _, err = archive.Put(raw); err != nil {
		t.Fatal(err)
	}
	dirA, dirQ := archive.dir, queue.dir
	archive.Close()
	queue.Close()
	archive = openTest(t, dirA)
	queue = openTest(t, dirQ)
	w := NewWorker(archive, queue)
	if !stepAt(w, time.Now()) {
		t.Fatal("replay failed")
	}
	state := w.Status()
	if state.PendingBatches != 0 || state.PendingBytes != 0 || state.Completed != 1 || state.Duplicates != 1 || len(archive.List()) != 1 {
		t.Fatal(state)
	}
	page, err := archive.Query(m.ID, 0, 120, 0, 100)
	if err != nil || len(page.Items) != 2 || page.Import.Status.Loss != "unknown" {
		t.Fatal("data/state lost", err)
	}
	if _, err = os.Stat(filepath.Join(dirQ, m.ID+".jsonl")); !os.IsNotExist(err) {
		t.Fatal("acknowledged queue file remains")
	}
}
func TestWorkerCapacityBackoffRetainsDataAndRecovers(t *testing.T) {
	archive, queue := workerStores(t)
	w := NewWorker(archive, queue)
	raw := fixture(t)
	if _, _, err := w.Enqueue(raw); err != nil {
		t.Fatal(err)
	}
	archive.maxBytes = 1
	now := time.Now()
	if stepAt(w, now) {
		t.Fatal("full archive accepted")
	}
	state := w.Status()
	if state.State != "backoff" || state.PendingBatches != 1 || state.NextRetryAt == nil || *state.LastError != "storage_full" {
		t.Fatal(state)
	}
	if stepAt(w, now.Add(500*time.Millisecond)) {
		t.Fatal("ignored backoff")
	}
	if w.Status().Failures != 1 {
		t.Fatal("retry ran early")
	}
	archive.maxBytes = MaxStoreBytes
	if !stepAt(w, now.Add(time.Second)) {
		t.Fatal("recovery failed")
	}
	state = w.Status()
	if state.LastError != nil || state.NextRetryAt != nil || state.PendingBatches != 0 || state.ConsecutiveFailures != 0 {
		t.Fatal(state)
	}
}
func TestWorkerExponentialBackoffIsBoundedAndQueueBackpressureIsExplicit(t *testing.T) {
	archive, queue := workerStores(t)
	w := NewWorker(archive, queue)
	queue.maxBytes = 1
	if _, _, err := w.Enqueue(fixture(t)); !errors.Is(err, ErrFull) {
		t.Fatal("missing queue backpressure", err)
	}
	queue.maxBytes = MaxStoreBytes
	if _, _, err := w.Enqueue(fixture(t)); err != nil {
		t.Fatal(err)
	}
	archive.maxBytes = 1
	now := time.Now()
	for n := 0; n < 10; n++ {
		stepAt(w, now)
		state := w.Status()
		next, err := time.Parse(time.RFC3339Nano, *state.NextRetryAt)
		if err != nil || next.Sub(now) > 30*time.Second || next.Sub(now) < time.Second {
			t.Fatal("unbounded retry", state, err)
		}
		now = next
	}
	if len(queue.List()) != 1 || len(archive.List()) != 0 {
		t.Fatal("failed work was dropped")
	}
}
func TestWorkerIOFailureRetriesWithoutLeakingPaths(t *testing.T) {
	archive, queue := workerStores(t)
	w := NewWorker(archive, queue)
	if _, _, err := w.Enqueue(fixture(t)); err != nil {
		t.Fatal(err)
	}
	dir := archive.dir
	if err := os.Rename(dir, dir+"-held"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	stepAt(w, now)
	state := w.Status()
	if state.LastError == nil || *state.LastError != "storage_io" || state.PendingBatches != 1 {
		t.Fatal(state)
	}
	if err := os.Rename(dir+"-held", dir); err != nil {
		t.Fatal(err)
	}
	if !stepAt(w, now.Add(time.Second)) {
		t.Fatal("transient storage error did not recover")
	}
}
func TestWorkerCorruptQueueAndUncertainStorageBlockWithoutDeletingSource(t *testing.T) {
	archive, queue := workerStores(t)
	w := NewWorker(archive, queue)
	m, _, err := w.Enqueue(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(queue.dir, m.ID+".jsonl")
	if err := os.WriteFile(p, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	stepAt(w, now)
	if state := w.Status(); state.State != "blocked" || *state.LastError != "queue_data_invalid" || state.PendingBatches != 1 {
		t.Fatal(state)
	}
	if stepAt(w, now.Add(time.Hour)) {
		t.Fatal("blocked data was retried")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("corrupt evidence was deleted")
	}
	archive2, queue2 := workerStores(t)
	w2 := NewWorker(archive2, queue2)
	archive2.failed = true
	stepAt(w2, now)
	if state := w2.Status(); state.State != "blocked" || *state.LastError != "storage_requires_restart" {
		t.Fatal(state)
	}
}
func TestWorkerCancellationLeavesDurablePendingBatch(t *testing.T) {
	archive, queue := workerStores(t)
	archive.maxBytes = 1
	w := NewWorker(archive, queue)
	if _, _, err := w.Enqueue(fixture(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for w.Status().State != "backoff" {
		if time.Now().After(deadline) {
			t.Fatal("worker did not process")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop")
	}
	if s := w.Status(); s.Running || s.State != "stopped" || s.PendingBatches != 1 {
		t.Fatal(s)
	}
}
func TestQueueOrderUsesChronologicalNanoseconds(t *testing.T) {
	_, q := workerStores(t)
	raw := fixture(t)
	a, _, err := q.Put(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	b.Status.AnalysisComplete = false
	z, _, err := q.Put(canonical(b))
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1000, 0)
	for id, ts := range map[string]time.Time{a.ID: stamp, z.ID: stamp.Add(100 * time.Millisecond)} {
		if err := os.Chtimes(filepath.Join(q.dir, id+".jsonl"), ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	dir := q.dir
	q.Close()
	q = openTest(t, dir)
	list := q.List()
	if list[0].ID != z.ID || list[1].ID != a.ID {
		t.Fatal("whole second sorted after fractional second")
	}
}

func TestBackoffStartsWhenFailedAttemptFinishes(t *testing.T) {
	archive, queue := workerStores(t)
	archive.maxBytes = 1
	w := NewWorker(archive, queue)
	if _, _, err := w.Enqueue(fixture(t)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return now
		}
		return now.Add(5 * time.Second)
	}
	if w.step(clock) {
		t.Fatal("full store accepted")
	}
	next, err := time.Parse(time.RFC3339Nano, *w.Status().NextRetryAt)
	if err != nil || !next.Equal(now.Add(6*time.Second)) {
		t.Fatal("backoff measured from attempt start", next, err)
	}
}
