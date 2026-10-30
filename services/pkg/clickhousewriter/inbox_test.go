package clickhousewriter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

func inboxConfig(t *testing.T) InboxConfig {
	t.Helper()
	return InboxConfig{Directory: t.TempDir(), Queue: Config{
		Directory: filepath.Join(t.TempDir(), "spool"), Target: "native://test/db/table",
		MaxPendingBytes: 4096, RetryInterval: time.Millisecond, MaxAttempts: 2,
	}, BatchRows: 1, BatchBytes: 128, MaxSources: 10, PollInterval: time.Millisecond}
}

func publishInbox(t *testing.T, cfg InboxConfig, name, data string) {
	t.Helper()
	tmp := filepath.Join(cfg.Directory, ".publishing.tmp")
	if err := os.WriteFile(tmp, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(cfg.Directory, name)); err != nil {
		t.Fatal(err)
	}
}

func openInbox(t *testing.T, cfg InboxConfig) *Inbox {
	t.Helper()
	in, err := OpenInbox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := in.Close(); err != nil {
			t.Error(err)
		}
	})
	return in
}

func TestInboxIndependentPublicationsRestartAndIdentity(t *testing.T) {
	cfg := inboxConfig(t)
	publishInbox(t, cfg, "b.jsonl", "{\"n\":1}\n")
	publishInbox(t, cfg, "a.jsonl", "{\"n\":1}\n")
	if err := os.WriteFile(filepath.Join(cfg.Directory, ".unpublished.jsonl"), []byte("unfinished"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Directory, "c.jsonl.tmp"), []byte("unfinished"), 0600); err != nil {
		t.Fatal(err)
	}
	var names, ids []string
	cfg.OnComplete = func(name string, s Stats) {
		names = append(names, name)
		if s.SourceOffset != s.SourceSize || s.PendingBatches != 0 {
			t.Error("未完成的源不能确认", s)
		}
	}
	send := func(_ context.Context, id string, data []byte) error {
		ids = append(ids, id)
		if string(data) != "{\"n\":1}\n" {
			t.Error(string(data))
		}
		return nil
	}
	in := openInbox(t, cfg)
	if err := in.Scan(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"a.jsonl", "b.jsonl"}) || len(ids) != 2 || ids[0] == ids[1] {
		t.Fatal(names, ids)
	}
	if s := in.Stats(); s.CompletedSources != 2 || s.DeliveredRows != 2 || s.KnownSources != 2 {
		t.Fatal(s)
	}
	if err := in.Scan(context.Background(), send); err != nil || len(ids) != 2 {
		t.Fatal(err, ids)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	in = openInbox(t, cfg)
	if err := in.Scan(context.Background(), send); err != nil || len(ids) != 2 {
		t.Fatal("重启不应重送已完成源", err, ids)
	}
	if s := in.Stats(); s.CompletedSources != 2 || s.DeliveredRows != 0 {
		t.Fatal(s)
	}
	// Even an equal-size mutation with its old timestamp restored is detected on restart.
	path := filepath.Join(cfg.Directory, "a.jsonl")
	old, _ := os.Stat(path)
	if err := os.WriteFile(path, []byte("{\"n\":2}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old.ModTime(), old.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	in = openInbox(t, cfg)
	if err := in.Scan(context.Background(), send); err == nil || len(ids) != 2 {
		t.Fatal("源变化须在重放前被拒绝", err, ids)
	}
}

func TestInboxFailureReplayPrecedesNewFiles(t *testing.T) {
	cfg := inboxConfig(t)
	publishInbox(t, cfg, "z.jsonl", "{\"n\":1}\n")
	var failed []string
	in := openInbox(t, cfg)
	err := in.Scan(context.Background(), func(_ context.Context, id string, _ []byte) error {
		failed = append(failed, id)
		return errors.New("connection lost after INSERT")
	})
	if err == nil || len(failed) != 2 || failed[0] != failed[1] || in.Stats().CompletedSources != 0 {
		t.Fatal(err, failed, in.Stats())
	}
	if s := in.Stats(); s.ActiveSource != "z.jsonl" || s.ActiveStats == nil || s.ActiveStats.PendingBatches != 1 {
		t.Fatal(s)
	}
	snapshot := in.Stats()
	snapshot.ActiveStats.PendingBatches = 0
	if in.Stats().ActiveStats.PendingBatches != 1 {
		t.Fatal("统计快照不能修改消费者状态")
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	// A newly published name sorts before the existing source, but cannot overtake recovery.
	publishInbox(t, cfg, "a.jsonl", "{\"n\":1}\n")
	in = openInbox(t, cfg)
	var ids []string
	if err := in.Scan(context.Background(), func(_ context.Context, id string, _ []byte) error { ids = append(ids, id); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != failed[0] || ids[1] == failed[0] {
		t.Fatal(ids, failed)
	}
	if s := in.Stats(); s.RecoveredRows != 1 || s.DeliveredRows != 2 || s.CompletedSources != 2 {
		t.Fatal(s)
	}
}

func TestInboxPollingCancellationAndExclusiveOwnership(t *testing.T) {
	cfg := inboxConfig(t)
	in := openInbox(t, cfg)
	if other, err := OpenInbox(cfg); err == nil {
		other.Close()
		t.Fatal("重复进程未被拒绝")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var once sync.Once
	done := make(chan error, 1)
	go func() {
		done <- in.Run(ctx, func(ctx context.Context, _ string, _ []byte) error {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	publishInbox(t, cfg, "new.jsonl", "{\"n\":1}\n")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("没有发现新发布文件")
	}
	if err := in.Close(); err == nil {
		t.Fatal("运行中不能释放目录锁")
	}
	if err := in.Scan(ctx, func(context.Context, string, []byte) error { return nil }); err == nil {
		t.Fatal("并发扫描未被拒绝")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if in.Stats().CompletedSources != 0 {
		t.Fatal("取消不能变成完成确认")
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	in = openInbox(t, cfg)
	var count int
	if err := in.Scan(context.Background(), func(context.Context, string, []byte) error { count++; return nil }); err != nil || count != 1 {
		t.Fatal(err, count)
	}
}

func TestInboxRejectsUnsafeSourcesAndLimitsBeforeSending(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "fifo", "limit"} {
		t.Run(kind, func(t *testing.T) {
			cfg := inboxConfig(t)
			path := filepath.Join(cfg.Directory, "bad.jsonl")
			switch kind {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				os.WriteFile(outside, []byte("{\"n\":1}\n"), 0600)
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "limit":
				cfg.MaxSources = 1
				publishInbox(t, cfg, "a.jsonl", "{}\n")
				publishInbox(t, cfg, "b.jsonl", "{}\n")
			}
			in := openInbox(t, cfg)
			if err := in.Scan(context.Background(), func(context.Context, string, []byte) error { t.Error("拒绝前不应发送"); return nil }); err == nil {
				t.Fatal("危险源/超限未被拒绝")
			}
		})
	}
}

func TestInboxBindingCorruptionAndMissingSourceFailClosed(t *testing.T) {
	cfg := inboxConfig(t)
	publishInbox(t, cfg, "one.jsonl", "{}\n")
	in := openInbox(t, cfg)
	if err := in.Scan(context.Background(), func(context.Context, string, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []InboxConfig{func() InboxConfig { c := cfg; c.Queue.Target = "other"; return c }(), func() InboxConfig { c := cfg; c.Directory = t.TempDir(); return c }()} {
		if other, err := OpenInbox(changed); err == nil {
			other.Close()
			t.Fatal("目录/目标改投未被拒绝")
		}
	}
	in = openInbox(t, cfg)
	if err := os.Remove(filepath.Join(cfg.Directory, "one.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := in.Scan(context.Background(), func(context.Context, string, []byte) error { t.Error("源缺失时不能发送"); return nil }); err == nil {
		t.Fatal("源缺失未被拒绝")
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Queue.Directory, ".inbox"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenInbox(cfg); err == nil {
		other.Close()
		t.Fatal("绑定损坏未被拒绝")
	}
}

func TestInboxRejectsOverlappingDirectories(t *testing.T) {
	for _, inside := range []bool{true, false} {
		cfg := inboxConfig(t)
		if inside {
			cfg.Queue.Directory = filepath.Join(cfg.Directory, "spool")
		} else {
			cfg.Queue.Directory = filepath.Dir(cfg.Directory)
		}
		if in, err := OpenInbox(cfg); err == nil {
			in.Close()
			t.Fatal("重叠目录未被拒绝")
		}
	}
}

func TestInboxRejectsSourceReplacedAfterScan(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			cfg := inboxConfig(t)
			publishInbox(t, cfg, "race.jsonl", "{}\n")
			path := filepath.Join(cfg.Directory, "race.jsonl")
			expected, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				err = os.Symlink(path+".old", path)
			} else {
				err = syscall.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			in := openInbox(t, cfg)
			done := make(chan error, 1)
			go func() {
				_, err := in.consume(context.Background(), "race.jsonl", expected, func(context.Context, string, []byte) error {
					t.Error("replaced source cannot be sent")
					return nil
				})
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("source replacement was accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("opening a replaced FIFO blocked the consumer")
			}
		})
	}
}

func TestInboxDirectoryCaseAliasesUseFilesystemIdentity(t *testing.T) {
	root := t.TempDir()
	upper, lower := filepath.Join(root, "Incoming"), filepath.Join(root, "incoming")
	if err := os.Mkdir(upper, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lower, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := os.Stat(upper)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(lower)
	if err != nil {
		t.Fatal(err)
	}
	cfg := inboxConfig(t)
	cfg.Directory = upper
	cfg.Queue.Directory = filepath.Join(lower, "state")
	in, err := OpenInbox(cfg)
	if os.SameFile(a, b) {
		if err == nil {
			in.Close()
			t.Fatal("大小写别名不能绕过目录边界")
		}
	} else {
		if err != nil {
			t.Fatal("大小写敏感文件系统上的独立目录应可用", err)
		}
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
