package aggregate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// IngestStatus contains bounded aggregate operational state, never queue paths or payloads.
// Attempt counters are process-local; pending counts are recovered from durable files.
type IngestStatus struct {
	Enabled             bool    `json:"enabled"`
	Running             bool    `json:"running"`
	State               string  `json:"state"`
	PendingBatches      int     `json:"pending_batches"`
	PendingBytes        int64   `json:"pending_bytes"`
	MaxBatches          int     `json:"max_batches"`
	MaxBytes            int64   `json:"max_bytes"`
	OldestQueuedAt      *string `json:"oldest_queued_at"`
	NextRetryAt         *string `json:"next_retry_at"`
	LastError           *string `json:"last_error"`
	Completed           uint64  `json:"completed_this_process"`
	Duplicates          uint64  `json:"duplicates_this_process"`
	Failures            uint64  `json:"failures_this_process"`
	ConsecutiveFailures uint64  `json:"consecutive_failures"`
}
type Worker struct {
	queue   *Store
	archive *Store
	mu      sync.Mutex
	status  IngestStatus
	retryAt time.Time
	blocked bool
}

func NewWorker(archive, queue *Store) *Worker {
	return &Worker{queue: queue, archive: archive, status: IngestStatus{Enabled: true, State: "stopped", MaxBatches: MaxImports, MaxBytes: MaxStoreBytes}}
}
func (w *Worker) Enqueue(data []byte) (Import, bool, error) { return w.queue.Put(data) }
func (w *Worker) Status() IngestStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.status
	items := w.queue.List()
	s.PendingBatches = len(items)
	for _, item := range items {
		s.PendingBytes += item.Bytes
	}
	if len(items) > 0 {
		oldest := items[len(items)-1].StoredAt
		s.OldestQueuedAt = &oldest
	}
	return s
}
func (w *Worker) fail(now time.Time, code string, permanent bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.Failures++
	w.status.ConsecutiveFailures++
	w.status.LastError = &code
	w.blocked = permanent
	if permanent {
		w.status.State = "blocked"
		w.status.NextRetryAt = nil
		return
	}
	delay := time.Second
	for n := uint64(1); n < w.status.ConsecutiveFailures && delay < 30*time.Second; n++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	w.retryAt = now.Add(delay)
	next := w.retryAt.UTC().Format(time.RFC3339Nano)
	w.status.NextRetryAt = &next
	w.status.State = "backoff"
}

// step processes at most one batch. Retrying after an archive commit is safe:
// the archive deduplicates before the queue's acknowledged file is removed.
func (w *Worker) step(clock func() time.Time) bool {
	now := clock()
	w.mu.Lock()
	wait := w.blocked || now.Before(w.retryAt)
	w.mu.Unlock()
	if wait {
		return false
	}
	if !w.queue.ready() {
		w.fail(clock(), "queue_requires_restart", true)
		return false
	}
	if !w.archive.ready() {
		w.fail(clock(), "storage_requires_restart", true)
		return false
	}
	items := w.queue.List()
	if len(items) == 0 {
		w.mu.Lock()
		w.status.State = "idle"
		w.mu.Unlock()
		return false
	}
	id := items[len(items)-1].ID
	w.mu.Lock()
	w.status.State = "writing"
	w.mu.Unlock()
	data, err := w.queue.readCommitted(id)
	if err != nil {
		w.fail(clock(), "queue_data_invalid", true)
		return false
	}
	_, duplicate, err := w.archive.Put(data)
	if err != nil {
		if !w.archive.ready() {
			w.fail(clock(), "storage_requires_restart", true)
		} else if errors.Is(err, ErrFull) {
			w.fail(clock(), "storage_full", false)
		} else if errors.Is(err, ErrInvalid) {
			w.fail(clock(), "storage_data_invalid", true)
		} else {
			w.fail(clock(), "storage_io", false)
		}
		return false
	}
	if err = w.queue.acknowledge(id); err != nil {
		w.fail(clock(), "queue_ack_failed", true)
		return false
	}
	w.mu.Lock()
	w.status.Completed++
	if duplicate {
		w.status.Duplicates++
	}
	w.status.ConsecutiveFailures = 0
	w.status.LastError = nil
	w.status.NextRetryAt = nil
	w.retryAt = time.Time{}
	w.status.State = "idle"
	w.mu.Unlock()
	return true
}

// Run is owned by telemetryd: shutdown drains in-flight HTTP requests first,
// then cancels this worker before closing either store. Pending files survive.
func (w *Worker) Run(ctx context.Context) {
	w.mu.Lock()
	w.status.Running = true
	w.status.State = "idle"
	w.mu.Unlock()
	defer func() { w.mu.Lock(); w.status.Running = false; w.status.State = "stopped"; w.mu.Unlock() }()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		for n := 0; n < 8; n++ {
			if ctx.Err() != nil {
				return
			}
			if !w.step(time.Now) {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
