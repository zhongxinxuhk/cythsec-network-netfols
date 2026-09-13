package dns

import (
	"errors"
	"sync"
	"testing"
)

func TestNormalizeZoneName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com."},      // 补结尾点
		{"example.com.", "example.com."},     // 已带点则保持
		{"Example.COM", "example.com."},      // 统一小写
		{"  example.com  ", "example.com."},  // 去首尾空白
		{"  EXAMPLE.com.  ", "example.com."}, // 组合场景
		{"", ""},                             // 空串
		{"   ", ""},                          // 纯空白
		{".", "."},                           // 根区域
		{"com", "com."},                      // 顶级域
		{"a.b.c.d.e.f", "a.b.c.d.e.f."},      // 多级
	}
	for _, c := range cases {
		if got := NormalizeZoneName(c.in); got != c.want {
			t.Errorf("NormalizeZoneName(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestStoreLookupIsCaseAndDotInsensitive 是规范化的行为契约：
// 调用方无论用何种写法，都应命中同一区域。
//
// 若此处失败，说明规范化未贯穿「写入」与「查找」两端 —— DNS 域名大小写
// 不敏感（RFC 4343），不一致会导致静默漏命中。
func TestStoreLookupIsCaseAndDotInsensitive(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Zone{Name: "Example.COM"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	for _, q := range []string{"example.com.", "example.com", "EXAMPLE.COM", "  Example.Com.  "} {
		z, ok := s.Get(q)
		if !ok {
			t.Errorf("查询 %q 未命中（规范化未贯穿查找路径）", q)
			continue
		}
		if z.Name != "example.com." {
			t.Errorf("查询 %q 得到区域名 %q，期望规范化后的 example.com.", q, z.Name)
		}
	}
}

func TestStorePutGetDelete(t *testing.T) {
	s := NewStore()

	if got := s.Count(); got != 0 {
		t.Fatalf("初始区域数 = %d，期望 0", got)
	}
	if _, ok := s.Get("nope.example."); ok {
		t.Error("空存储不应查到任何区域")
	}

	isNew, err := s.Put(Zone{Name: "example.com", Records: []Record{
		{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
	}})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !isNew {
		t.Error("首次写入应报告 isNew=true")
	}

	// 覆盖写不应新增条目，且应替换记录集。
	isNew, err = s.Put(Zone{Name: "example.com", Records: []Record{
		{Name: "api", Type: "A", TTL: 60, Value: "192.0.2.2"},
		{Name: "www", Type: "CNAME", TTL: 60, Value: "api.example.com."},
	}})
	if err != nil {
		t.Fatalf("Put(覆盖): %v", err)
	}
	if isNew {
		t.Error("覆盖写应报告 isNew=false")
	}
	if got := s.Count(); got != 1 {
		t.Errorf("覆盖后区域数 = %d，期望 1", got)
	}

	z, ok := s.Get("example.com")
	if !ok {
		t.Fatal("应能查到 example.com")
	}
	if len(z.Records) != 2 {
		t.Errorf("覆盖后记录数 = %d，期望 2（应为替换而非追加）", len(z.Records))
	}
	if got := s.RecordCount(); got != 2 {
		t.Errorf("RecordCount = %d，期望 2", got)
	}

	// 用规范化等价写法删除，也应成功。
	if !s.Delete("EXAMPLE.com.") {
		t.Error("删除已存在区域（等价写法）应返回 true")
	}
	if s.Delete("example.com") {
		t.Error("重复删除应返回 false")
	}
	if got := s.Count(); got != 0 {
		t.Errorf("删除后区域数 = %d，期望 0", got)
	}
}

func TestStorePutRejectsEmptyName(t *testing.T) {
	s := NewStore()
	for _, name := range []string{"", "   "} {
		if _, err := s.Put(Zone{Name: name}); !errors.Is(err, ErrEmptyZoneName) {
			t.Errorf("Put(%q) 应返回 ErrEmptyZoneName，实际 %v", name, err)
		}
	}
	if got := s.Count(); got != 0 {
		t.Errorf("被拒绝的写入不应留下条目，区域数 = %d", got)
	}
}

func TestStoreListKeepsInsertOrder(t *testing.T) {
	s := NewStore()
	for _, name := range []string{"c.example", "a.example", "b.example"} {
		if _, err := s.Put(Zone{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.List()
	want := []string{"c.example.", "a.example.", "b.example."}
	if len(got) != len(want) {
		t.Fatalf("区域数 = %d，期望 %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("第 %d 个 = %q，期望 %q（应保持插入顺序）", i, got[i].Name, want[i])
		}
	}

	// 删除中间一个后顺序应保持稳定。
	if !s.Delete("a.example") {
		t.Fatal("删除 a.example 失败")
	}
	got = s.List()
	if len(got) != 2 || got[0].Name != "c.example." || got[1].Name != "b.example." {
		t.Errorf("删除后顺序异常: %+v", got)
	}
}

// TestStoreReturnsCopies 校验存储不向外泄漏内部引用。
//
// 缺少此保护时，调用方改写返回的记录切片会静默污染存储内部状态，
// 且因无并发写而难以复现。
func TestStoreReturnsCopies(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Zone{Name: "example.com", Records: []Record{{Name: "www", Value: "192.0.2.1"}}}); err != nil {
		t.Fatal(err)
	}

	// 场景 1：调用方修改写入时的切片。
	recs := []Record{{Name: "www", Type: "A", Value: "192.0.2.1"}}
	if _, err := s.Put(Zone{Name: "other.example", Records: recs}); err != nil {
		t.Fatal(err)
	}
	recs[0].Value = "被外部篡改"

	// 场景 2：调用方修改 Get 返回值。
	z, _ := s.Get("example.com")
	z.Records[0].Value = "被外部篡改"

	// 场景 3：调用方修改 List 返回值。
	list := s.List()
	for i := range list {
		list[i].Records = append(list[i].Records, Record{Name: "注入", Value: "1.2.3.4"})
	}

	fresh, _ := s.Get("other.example")
	if fresh.Records[0].Value == "被外部篡改" {
		t.Error("Put 未复制传入的记录切片，外部修改污染了存储")
	}
	fresh, _ = s.Get("example.com")
	if fresh.Records[0].Value == "被外部篡改" {
		t.Error("Get 返回了内部引用，外部修改污染了存储")
	}
	if got := s.RecordCount(); got != 2 {
		t.Errorf("RecordCount = %d，期望 2（外部追加的记录不应进入存储）", got)
	}
}

func TestStoreLoadReplacesAll(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Zone{Name: "old.example", Records: []Record{{Name: "x"}}}); err != nil {
		t.Fatal(err)
	}

	if err := s.Load([]Zone{
		{Name: "n1.example", Records: []Record{{Name: "a"}, {Name: "b"}}},
		{Name: "n2.example"},
	}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.Count(); got != 2 {
		t.Errorf("区域数 = %d，期望 2", got)
	}
	if got := s.RecordCount(); got != 2 {
		t.Errorf("记录数 = %d，期望 2", got)
	}
	if _, ok := s.Get("old.example"); ok {
		t.Error("Load 应全量替换，旧区域不应残留")
	}
	if got := s.List(); got[0].Name != "n1.example." || got[1].Name != "n2.example." {
		t.Errorf("Load 后顺序异常: %+v", got)
	}
}

// TestStoreLoadRejectsBadInput 同时校验「先全量校验、后替换」的原子性。
func TestStoreLoadRejectsBadInput(t *testing.T) {
	s := NewStore()
	if _, err := s.Put(Zone{Name: "keep.example", Records: []Record{{Name: "a"}, {Name: "b"}}}); err != nil {
		t.Fatal(err)
	}

	if err := s.Load([]Zone{{Name: "x.example"}, {Name: ""}}); err == nil {
		t.Error("含空区域名应报错")
	}
	// 大小写不同的同名区域在规范化后相同，也应判为重复。
	if err := s.Load([]Zone{{Name: "dup.example"}, {Name: "DUP.example."}}); err == nil {
		t.Error("规范化后重复的区域名应报错")
	}

	// 校验失败时不得破坏现有数据。
	if got := s.Count(); got != 1 {
		t.Errorf("校验失败后区域数 = %d，期望保持 1", got)
	}
	if got := s.RecordCount(); got != 2 {
		t.Errorf("校验失败后记录数 = %d，期望保持 2", got)
	}
	if _, ok := s.Get("keep.example"); !ok {
		t.Error("校验失败后原有区域应完好")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				name := string(rune('a'+n)) + "-" + string(rune('0'+j%10)) + ".example"
				if _, err := s.Put(Zone{Name: name, Records: []Record{{Name: "www"}}}); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.List()
				_ = s.Count()
				_ = s.RecordCount()
				_, _ = s.Get("a-0.example")
				_ = s.Delete("zzz-not-exist.example")
			}
		}()
	}
	wg.Wait()

	if got := s.Count(); got == 0 {
		t.Error("并发写入后不应为空")
	}
	if got := s.RecordCount(); got != s.Count() {
		t.Errorf("每个区域各 1 条记录，记录数 %d 应等于区域数 %d", got, s.Count())
	}
}
