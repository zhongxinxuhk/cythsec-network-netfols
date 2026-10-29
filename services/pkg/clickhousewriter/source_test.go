package clickhousewriter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceFile(t *testing.T, data string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.jsonl")
	if e := os.WriteFile(path, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestSourceRejectsOverlappingRangesEvenBelowCheckpoint(t *testing.T) {
	cfg := config(t)
	cfg.MaxPendingBytes = 4096
	f := sourceFile(t, "{\"n\":1}\n{\"n\":2}\n")
	q := openQueue(t, cfg)
	if e := q.ConsumeFile(context.Background(), f, 1, 100); e != nil {
		t.Fatal(e)
	}
	q.Close()
	files, _ := filepath.Glob(filepath.Join(cfg.Directory, "*.batch"))
	data, e := os.ReadFile(files[1])
	if e != nil {
		t.Fatal(e)
	}
	var b batch
	if e = json.Unmarshal(data, &b); e != nil {
		t.Fatal(e)
	}
	b.Source.Start = 0
	b.Source.Checksum = rangeChecksum(*b.Source, b.SHA256)
	data, _ = json.Marshal(b)
	if e = os.WriteFile(files[1], data, 0600); e != nil {
		t.Fatal(e)
	}
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("接收高水位以下的重叠被静默接受")
	} else if !strings.Contains(e.Error(), "重叠") {
		t.Fatal(e)
	}
}

func TestSourceRecoversBatchBeforeCheckpointAndDoesNotResend(t *testing.T) {
	cfg := config(t)
	cfg.MaxPendingBytes = 4096
	f := sourceFile(t, " \r\n{\"n\":1}\r\n\n{\"n\":2}")
	q := openQueue(t, cfg)
	if e := q.BindFile(f); e != nil {
		t.Fatal(e)
	}
	old, e := os.ReadFile(filepath.Join(cfg.Directory, ".source"))
	if e != nil {
		t.Fatal(e)
	}
	if e = q.ConsumeFile(context.Background(), f, 1, 100); e != nil {
		t.Fatal(e)
	}
	if q.Stats().SourceRows != 2 || q.Stats().SourceOffset != int64(len(" \r\n{\"n\":1}\r\n\n{\"n\":2}")) {
		t.Fatal(q.Stats())
	}
	q.Close()
	// 模拟批次文件已经持久化，但 .source 仍是旧高水位的中断窗口。
	if e = os.WriteFile(filepath.Join(cfg.Directory, ".source"), old, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(cfg.Directory, ".pending-checkpoint.tmp"), []byte("partial checkpoint"), 0600); e != nil {
		t.Fatal(e)
	}
	q = openQueue(t, cfg)
	if q.Stats().SourceRows != 2 || q.Stats().RecoveredRows != 2 || q.Stats().UncommittedTemps != 1 {
		t.Fatal(q.Stats())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	sent := 0
	go func() { done <- q.Run(ctx, func(context.Context, string, []byte) error { sent++; return nil }) }()
	if e = q.WaitEmpty(ctx); e != nil {
		t.Fatal(e)
	}
	cancel()
	<-done
	q.Close()
	if sent != 2 {
		t.Fatal(sent)
	}
	q = openQueue(t, cfg)
	defer q.Close()
	if e = q.ConsumeFile(context.Background(), f, 1, 100); e != nil {
		t.Fatal(e)
	}
	if q.Stats().AcceptedRows != 0 || q.Stats().PendingBatches != 0 || q.Stats().SourceRows != 2 {
		t.Fatal(q.Stats())
	}
}

func TestSourceRejectsChangedInputAndCorruptRange(t *testing.T) {
	cfg := config(t)
	cfg.MaxPendingBytes = 4096
	f := sourceFile(t, "{\"n\":1}\n{\"n\":2}\n")
	q := openQueue(t, cfg)
	if e := q.ConsumeFile(context.Background(), f, 1, 100); e != nil {
		t.Fatal(e)
	}
	if e := q.Enqueue(context.Background(), []byte("{}\n")); e == nil {
		t.Fatal("断点队列接受了无源批次")
	}
	if e := os.WriteFile(f.Name(), []byte("{\"n\":9}\n{\"n\":2}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := q.BindFile(f); e == nil {
		t.Fatal("等长修改未被拒绝")
	}
	q.Close()
	files, _ := filepath.Glob(filepath.Join(cfg.Directory, "*.batch"))
	data, e := os.ReadFile(files[0])
	if e != nil {
		t.Fatal(e)
	}
	var b batch
	if e = json.Unmarshal(data, &b); e != nil {
		t.Fatal(e)
	}
	b.Source.End--
	data, _ = json.Marshal(b)
	if e = os.WriteFile(files[0], data, 0600); e != nil {
		t.Fatal(e)
	}
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("源偏移损坏未被拒绝")
	}
}

func TestSourceCheckpointAndTargetMustRemainIntact(t *testing.T) {
	f := sourceFile(t, "\r\n \n")
	cfg := config(t)
	q := openQueue(t, cfg)
	if e := q.ConsumeFile(context.Background(), f, 10, 100); e != nil {
		t.Fatal(e)
	}
	if q.Stats().SourceOffset != 4 || q.Stats().SourceRows != 0 {
		t.Fatal(q.Stats())
	}
	q.Close()
	path := filepath.Join(cfg.Directory, ".source")
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var s sourceState
	if e = json.Unmarshal(data, &s); e != nil {
		t.Fatal(e)
	}
	s.Offset--
	bad, _ := json.Marshal(s)
	os.WriteFile(path, bad, 0600)
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("检查点损坏未被拒绝")
	}
	os.WriteFile(path, data, 0600)
	os.Remove(filepath.Join(cfg.Directory, ".target"))
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("没有目标绑定时错误恢复了断点")
	}
}
