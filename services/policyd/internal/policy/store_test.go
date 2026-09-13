package policy

import (
	"errors"
	"sync"
	"testing"
)

func TestStorePutGetDelete(t *testing.T) {
	s := NewStore()

	if got := s.Count(); got != 0 {
		t.Fatalf("初始条数 = %d，期望 0", got)
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("空存储不应查到任何规则")
	}

	isNew, err := s.Put(Rule{ID: "r1", Name: "默认放行", Priority: 10, Enabled: true})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !isNew {
		t.Error("首次写入应报告 isNew=true")
	}

	// 覆盖写不应新增条目。
	isNew, err = s.Put(Rule{ID: "r1", Name: "改名后", Priority: 20, Enabled: false})
	if err != nil {
		t.Fatalf("Put(覆盖): %v", err)
	}
	if isNew {
		t.Error("覆盖写应报告 isNew=false")
	}
	if got := s.Count(); got != 1 {
		t.Errorf("覆盖后条数 = %d，期望 1", got)
	}

	r, ok := s.Get("r1")
	if !ok {
		t.Fatal("应能查到 r1")
	}
	if r.Name != "改名后" || r.Priority != 20 || r.Enabled {
		t.Errorf("覆盖未生效: %+v", r)
	}

	if !s.Delete("r1") {
		t.Error("删除已存在条目应返回 true")
	}
	if s.Delete("r1") {
		t.Error("重复删除应返回 false")
	}
	if got := s.Count(); got != 0 {
		t.Errorf("删除后条数 = %d，期望 0", got)
	}
}

func TestStorePutRejectsEmptyID(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Rule{ID: ""}); !errors.Is(err, ErrEmptyID) {
		t.Errorf("空 ID 应返回 ErrEmptyID，实际 %v", err)
	}
}

func TestStoreListKeepsInsertOrder(t *testing.T) {
	s := NewStore()
	for _, id := range []string{"c", "a", "b"} {
		if _, err := s.Put(Rule{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.List()
	want := []string{"c", "a", "b"}
	if len(got) != len(want) {
		t.Fatalf("条数 = %d，期望 %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Errorf("第 %d 条 = %q，期望 %q（应保持插入顺序）", i, got[i].ID, want[i])
		}
	}

	// 返回的必须是副本：修改返回值不应影响存储内部状态。
	got[0].Name = "被外部篡改"
	if r, _ := s.Get("c"); r.Name == "被外部篡改" {
		t.Error("List 返回了内部引用，外部修改污染了存储")
	}

	// 删除中间一条后顺序应保持稳定。
	if !s.Delete("a") {
		t.Fatal("删除 a 失败")
	}
	got = s.List()
	if len(got) != 2 || got[0].ID != "c" || got[1].ID != "b" {
		t.Errorf("删除后顺序异常: %+v", got)
	}
}

func TestStoreLoadReplacesAll(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Rule{ID: "old"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Load([]Rule{{ID: "n1"}, {ID: "n2"}}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.Count(); got != 2 {
		t.Errorf("条数 = %d，期望 2", got)
	}
	if _, ok := s.Get("old"); ok {
		t.Error("Load 应全量替换，旧条目不应残留")
	}
	if got := s.List(); got[0].ID != "n1" || got[1].ID != "n2" {
		t.Errorf("Load 后顺序异常: %+v", got)
	}
}

func TestStoreLoadRejectsBadInput(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Rule{ID: "keep"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Load([]Rule{{ID: "x"}, {ID: ""}}); err == nil {
		t.Error("含空 ID 应报错")
	}
	if err := s.Load([]Rule{{ID: "x"}, {ID: "x"}}); err == nil {
		t.Error("重复 ID 应报错")
	}
	// 校验失败时不得破坏现有数据（先校验后替换）。
	if got := s.Count(); got != 1 {
		t.Errorf("校验失败后条数 = %d，期望保持 1", got)
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup

	// 并发写。
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				id := string(rune('a'+n)) + "-" + string(rune('0'+j%10))
				if _, err := s.Put(Rule{ID: id}); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
			}
		}(i)
	}
	// 并发读。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.List()
				_ = s.Count()
				_, _ = s.Get("a-0")
			}
		}()
	}
	wg.Wait()

	if got := s.Count(); got == 0 {
		t.Error("并发写入后不应为空")
	}
}
