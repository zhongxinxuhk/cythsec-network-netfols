package clickhousewriter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func config(t *testing.T) Config {
	return Config{Directory: t.TempDir(), Target: "native://test/db/table", MaxPendingBytes: 300, RetryInterval: time.Millisecond, MaxAttempts: 2}
}
func openQueue(t *testing.T, cfg Config) *Queue {
	t.Helper()
	q, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func until(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !f() {
		select {
		case <-deadline:
			t.Fatal("等待条件超时")
		case <-tick.C:
		}
	}
}

func TestDurableFailureReplayAndTargetLock(t *testing.T) {
	cfg := config(t)
	q := openQueue(t, cfg)
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("第二个进程应被拒绝")
	}
	data := []byte("{\"a\":1}\n")
	if e := q.Enqueue(context.Background(), data); e != nil {
		t.Fatal(e)
	}
	var ids []string
	e := q.Run(context.Background(), func(_ context.Context, id string, got []byte) error {
		ids = append(ids, id)
		if !bytes.Equal(got, data) {
			t.Fatal("数据变化")
		}
		return errors.New("断网")
	})
	if e == nil || len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("重试未保留 token: %v %v", e, ids)
	}
	if s := q.Stats(); s.PendingBatches != 1 || s.AcceptedRows != 1 || s.DeliveredRows != 0 {
		t.Fatal(s)
	}
	if e = q.Close(); e != nil {
		t.Fatal(e)
	}
	wrong := cfg
	wrong.Target = "other"
	if other, e := Open(wrong); e == nil {
		other.Close()
		t.Fatal("不能重放到其他目标")
	}
	q = openQueue(t, cfg)
	defer q.Close()
	if q.Stats().RecoveredRows != 1 {
		t.Fatal("重启没有发现已确认接收的批次")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- q.Run(ctx, func(_ context.Context, id string, got []byte) error {
			if id != ids[0] || !bytes.Equal(got, data) {
				t.Error("重放的 ID/字节变化")
			}
			return nil
		})
	}()
	if e = q.WaitEmpty(context.Background()); e != nil {
		t.Fatal(e)
	}
	cancel()
	<-done
	if q.Stats().DeliveredRows != 1 || q.Stats().PendingBytes != 0 {
		t.Fatal(q.Stats())
	}
}

func TestBackpressureIncludesInFlightAndResumes(t *testing.T) {
	q := openQueue(t, config(t))
	defer q.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if e := q.Enqueue(ctx, []byte("{\"a\":1}\n")); e != nil {
		t.Fatal(e)
	}
	second := make(chan error, 1)
	go func() { second <- q.Enqueue(ctx, []byte("{\"a\":2}\n")) }()
	until(t, func() bool { return q.Stats().BackpressureWaits > 0 })
	select {
	case <-second:
		t.Fatal("满队列未阻塞")
	default:
	}
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	done := make(chan error, 1)
	go func() {
		done <- q.Run(ctx, func(context.Context, string, []byte) error { started <- struct{}{}; <-release; return nil })
	}()
	<-started
	select {
	case <-second:
		t.Fatal("正在发送的文件仍须占容量")
	default:
	}
	close(release)
	if e := <-second; e != nil {
		t.Fatal(e)
	}
	if e := q.WaitEmpty(ctx); e != nil {
		t.Fatal(e)
	}
	cancel()
	<-done
	if q.Stats().DeliveredRows != 2 {
		t.Fatal(q.Stats())
	}
}

func TestCancellationInvalidDataAndCorruptionRetainEvidence(t *testing.T) {
	cfg := config(t)
	q := openQueue(t, cfg)
	for _, data := range []string{"", "{}", "null\n", "{bad}\n", "{}\n\n"} {
		if e := q.Enqueue(context.Background(), []byte(data)); e == nil {
			t.Fatalf("接受了 %q", data)
		}
	}
	if e := q.Enqueue(context.Background(), []byte("{\"a\":1}\n")); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := q.Enqueue(ctx, []byte("{}\n")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if e := q.Enqueue(waitCtx, []byte("{}\n")); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("容量等待没有响应取消", e)
	}
	q.Close()
	files, _ := filepath.Glob(filepath.Join(cfg.Directory, "*.batch"))
	data, _ := os.ReadFile(files[0])
	var b batch
	json.Unmarshal(data, &b)
	b.Data = []byte("{\"a\":2}\n")
	data, _ = json.Marshal(b)
	os.WriteFile(files[0], data, 0600)
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("SHA256 损坏未被检出")
	}
	if _, e := os.Stat(files[0]); e != nil {
		t.Fatal("损坏证据被删除")
	}
	clean := config(t)
	cleanQueue := openQueue(t, clean)
	cleanQueue.Close()
	if e := os.WriteFile(filepath.Join(clean.Directory, ".pending-crash.tmp"), []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if other, e := Open(clean); e == nil {
		other.Close()
		t.Fatal("未完成文件未报错")
	}
}

func TestConsumeBoundariesAndTimer(t *testing.T) {
	var got []string
	enqueue := func(_ context.Context, b []byte) error { got = append(got, string(b)); return nil }
	if e := Consume(context.Background(), bytes.NewBufferString("{}\n{}\n{}"), 2, 7, time.Second, enqueue); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, []string{"{}\n{}\n", "{}\n"}) {
		t.Fatal(got)
	}
	if e := Consume(context.Background(), bytes.NewBufferString("{\"long\":1234567890}\n"), 2, 8, time.Second, enqueue); e == nil {
		t.Fatal("超长记录未拒绝")
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	flushed := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Consume(context.Background(), r, 10, 100, 10*time.Millisecond, func(_ context.Context, b []byte) error { flushed <- string(b); return nil })
	}()
	w.Write([]byte("{}\n"))
	select {
	case s := <-flushed:
		if s != "{}\n" {
			t.Fatal(s)
		}
	case <-time.After(time.Second):
		t.Fatal("尾批未按时刷新")
	}
	w.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestClientRejectsSQLIdentifiersAndBoundsErrors(t *testing.T) {
	c := Client{Binary: "client", Host: "localhost", User: "user", Database: "default", Table: "flows;DROP", Port: 9000, Timeout: time.Second}
	if c.Validate() == nil {
		t.Fatal("未拒绝 SQL 注入")
	}
	c.Table = "flows"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	var b errorBuffer
	if n, _ := b.Write(bytes.Repeat([]byte{'x'}, 100000)); n != 100000 || b.Len() != 4096 {
		t.Fatal("错误输出无界")
	}
}
