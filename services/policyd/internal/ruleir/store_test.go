// store_test.go —— 加载后端与版本化持有器的行为测试。
//
// 覆盖三种可实现后端（memory / json-file / index+datatable）、Redis 后端的显式不可用，
// 以及 Registry 的装载、拒绝、幂等与回滚语义。
package ruleir

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
	return path
}

func docJSON(t *testing.T, tables ...Table) string {
	t.Helper()
	data, err := json.Marshal(Doc{Tables: tables})
	if err != nil {
		t.Fatalf("序列化规则失败: %v", err)
	}
	return string(data)
}

func TestMemoryStoreIsolatedFromCaller(t *testing.T) {
	tbl := Table{Name: "T", Rules: []Rule{baseRule("r-1")}}
	store := NewMemoryStore(tbl)

	tbl.Rules[0].Name = "被调用方改了"

	tables, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if tables[0].Rules[0].Name != "r-1" {
		t.Fatalf("构造后调用方修改影响了后端内容: %s", tables[0].Rules[0].Name)
	}
	// Load 返回的也应是副本
	tables[0].Rules[0].Name = "又被改了"
	tables2, _ := store.Load(context.Background())
	if tables2[0].Rules[0].Name != "r-1" {
		t.Fatal("Load 返回值与后端共享底层切片")
	}
}

func TestFileStoreLoad(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "rules.json", docJSON(t, Table{Name: "T", Rules: []Rule{baseRule("r-1")}}))

	store := NewFileStore(path, 0)
	if store.Name() != "json-file" {
		t.Errorf("后端名错误: %s", store.Name())
	}
	tables, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(tables) != 1 || tables[0].Name != "T" {
		t.Fatalf("装载结果错误: %+v", tables)
	}
}

func TestFileStoreStrictDecode(t *testing.T) {
	dir := t.TempDir()
	// match_methd 是拼错的字段名：必须拒绝加载，而不是忽略后按默认方法匹配。
	bad := `{"tables":[{"name":"T","rules":[{"uuid":"r-1","enabled":true,
	        "conditions":[{"attribute":"ATTR_SERVER_FQDN","objects":[
	        {"expression":"a.example","match_methd":"full"}]}],
	        "action":{"kind":"deny"}}]}]}`
	path := writeFile(t, dir, "bad.json", bad)

	_, err := NewFileStore(path, 0).Load(context.Background())
	if err == nil {
		t.Fatal("字段名拼错时必须报错，否则会按默认方法静默放大匹配范围")
	}
	if !strings.Contains(err.Error(), "match_methd") {
		t.Errorf("错误信息应指出具体字段: %v", err)
	}
}

func TestFileStoreLimits(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "rules.json", docJSON(t,
		Table{Name: "T1"}, Table{Name: "T2"}))

	if _, err := NewFileStore(path, 1).Load(context.Background()); err == nil {
		t.Fatal("超过 max_tables 应报错")
	}
	if _, err := NewFileStore(filepath.Join(dir, "missing.json"), 0).Load(context.Background()); err == nil {
		t.Fatal("文件缺失应报错")
	}
	if _, err := NewFileStore(writeFile(t, dir, "empty.json", `{"tables":[]}`), 0).Load(context.Background()); err == nil {
		t.Fatal("空表列表应报错")
	}
}

func TestIndexDataTableStoreLoad(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "tables/security.json",
		docJSON(t, Table{Name: "SECURITY_RULE", Rules: []Rule{baseRule("r-1")}}))
	writeFile(t, dir, "tables/whitelist.json",
		docJSON(t, Table{Name: "ALLOWLIST", Rules: []Rule{baseRule("r-2")}}))
	index := writeFile(t, dir, "index.json",
		`{"tables":{"SECURITY_RULE":"tables/security.json","ALLOWLIST":"tables/whitelist.json"}}`)

	store := NewIndexDataTableStore(index, 0)
	if store.Name() != "index+datatable" {
		t.Errorf("后端名错误: %s", store.Name())
	}
	tables, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(tables) != 2 {
		t.Fatalf("应装载 2 张表，实际 %d", len(tables))
	}
	// 索引内表按名称排序装载，保证校验和可复现
	if tables[0].Name != "ALLOWLIST" || tables[1].Name != "SECURITY_RULE" {
		t.Fatalf("装载顺序应按表名排序，实际 %s/%s", tables[0].Name, tables[1].Name)
	}
}

func TestIndexDataTableStoreErrors(t *testing.T) {
	dir := t.TempDir()
	index := writeFile(t, dir, "index.json", `{"tables":{"T":"missing.json"}}`)
	if _, err := NewIndexDataTableStore(index, 0).Load(context.Background()); err == nil {
		t.Fatal("数据表文件缺失应报错")
	}

	index = writeFile(t, dir, "index2.json", `{"tables":{}}`)
	if _, err := NewIndexDataTableStore(index, 0).Load(context.Background()); err == nil {
		t.Fatal("空索引应报错")
	}

	index = writeFile(t, dir, "index3.json", `{"tables":{"a":"x.json"},"extra":1}`)
	if _, err := NewIndexDataTableStore(index, 0).Load(context.Background()); err == nil {
		t.Fatal("索引含未知字段应报错（严格解析）")
	}
}

func TestRedisStoreIsExplicitlyUnavailable(t *testing.T) {
	store := &RedisStore{Addr: "127.0.0.1:6379"}
	_, err := store.Load(context.Background())
	if err == nil {
		t.Fatal("未实现的 Redis 后端必须显式报错，而不是返回空表集")
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("错误应可被 errors.Is 识别: %v", err)
	}
	if !strings.Contains(err.Error(), "客户端依赖") {
		t.Errorf("错误信息应说明为何不可用: %v", err)
	}
}

func TestRegistryInstallAndRevision(t *testing.T) {
	reg := NewRegistry()

	if reg.Current() != nil {
		t.Fatal("初始状态应为空")
	}

	snap, err := reg.Install([]Table{{Name: "T", Rules: []Rule{baseRule("r-1")}}},
		CompileOptions{Mode: ModeOnPathInline}, "test")
	if err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if snap.Version.Revision != 1 {
		t.Fatalf("首个版本 revision 应为 1，实际 %d", snap.Version.Revision)
	}
	if len(snap.Version.Checksum) != 64 {
		t.Errorf("校验和应为 sha256 十六进制，实际 %q", snap.Version.Checksum)
	}

	// 内容未变：不应产生新版本
	snap2, err := reg.Install([]Table{{Name: "T", Rules: []Rule{baseRule("r-1")}}},
		CompileOptions{Mode: ModeOnPathInline}, "test")
	if err != nil {
		t.Fatalf("重复装载失败: %v", err)
	}
	if snap2.Version.Revision != 1 {
		t.Fatalf("内容未变时不应递增 revision，实际 %d", snap2.Version.Revision)
	}

	// 内容变化：递增
	mod := baseRule("r-1")
	mod.EvaluationOrder = 99
	snap3, err := reg.Install([]Table{{Name: "T", Rules: []Rule{mod}}},
		CompileOptions{Mode: ModeOnPathInline}, "test")
	if err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if snap3.Version.Revision != 2 {
		t.Fatalf("内容变化后 revision 应为 2，实际 %d", snap3.Version.Revision)
	}
	if reg.Previous() == nil || reg.Previous().Version.Revision != 1 {
		t.Fatal("应保留上一版本以便回滚")
	}
}

func TestRegistryRejectsInvalidTableAtomically(t *testing.T) {
	reg := NewRegistry()

	good := Table{Name: "T", Rules: []Rule{baseRule("r-1")}}
	if _, err := reg.Install([]Table{good}, CompileOptions{Mode: ModeOnPathInline}, "test"); err != nil {
		t.Fatalf("首次装载失败: %v", err)
	}
	before := reg.Current()

	// 一张冲突表 + 一张合法表：整体拒绝，不允许部分更新。
	conflictA := baseRule("r-a")
	conflictB := baseRule("r-b")
	conflictB.Action = Action{Kind: ActionAllow}
	_, err := reg.Install([]Table{
		{Name: "GOOD", Rules: []Rule{baseRule("r-2")}},
		{Name: "BAD", Rules: []Rule{conflictA, conflictB}},
	}, CompileOptions{Mode: ModeOnPathInline}, "test")
	if err == nil {
		t.Fatal("存在冲突时应拒绝装载")
	}
	if !errors.Is(err, ErrTableRejected) {
		t.Fatalf("错误应可被 errors.Is 识别: %v", err)
	}
	if !strings.Contains(err.Error(), "rule.conflict") {
		t.Errorf("拒绝原因应包含具体诊断码: %v", err)
	}
	if reg.Current() != before || reg.Current().Version.Revision != 1 {
		t.Fatal("装载失败后当前版本必须保持不变")
	}
}

func TestRegistryRollback(t *testing.T) {
	reg := NewRegistry()

	if reg.Rollback() {
		t.Fatal("无历史版本时回滚应返回 false")
	}

	v1 := Table{Name: "T", Rules: []Rule{baseRule("r-1")}}
	if _, err := reg.Install([]Table{v1}, CompileOptions{Mode: ModeOnPathInline}, "test"); err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	mod := baseRule("r-1")
	mod.EvaluationOrder = 42
	if _, err := reg.Install([]Table{{Name: "T", Rules: []Rule{mod}}},
		CompileOptions{Mode: ModeOnPathInline}, "test"); err != nil {
		t.Fatalf("装载失败: %v", err)
	}

	if !reg.Rollback() {
		t.Fatal("存在历史版本时应回滚成功")
	}
	if got := reg.Current().Tables["T"].Rules[0].order; got != 10 {
		t.Fatalf("回滚后应恢复旧版本内容，实际 order=%v", got)
	}
	if reg.Rollback() {
		t.Fatal("只保留一步历史：再次回滚应返回 false")
	}
}

func TestRegistryInputValidation(t *testing.T) {
	reg := NewRegistry()

	if _, err := reg.Install(nil, CompileOptions{}, "test"); err == nil {
		t.Error("空表集应报错")
	}
	if _, err := reg.Install([]Table{{Name: ""}}, CompileOptions{}, "test"); err == nil {
		t.Error("表缺少 name 应报错")
	}
	if _, err := reg.Install([]Table{{Name: "T"}, {Name: "T"}}, CompileOptions{}, "test"); err == nil {
		t.Error("表名重复应报错")
	}
	// 空规则表是合法的（例如预置一张待填充的白名单表），不应报错。
	if _, err := reg.Install([]Table{{Name: "EMPTY"}}, CompileOptions{}, "test"); err != nil {
		t.Errorf("空规则表应可装载: %v", err)
	}
}

func TestLoadAndInstallEndToEnd(t *testing.T) {
	dir := t.TempDir()
	rule := baseRule("r-blocked")
	rule.Protocol = "tcp"
	rule.Action = Action{Kind: ActionDeny, Params: ActionParams{
		SubActions: []SubAction{SubResetStream}, ResetCount: 1, ResetFlags: "rst_ack"}}
	path := writeFile(t, dir, "rules.json", docJSON(t, Table{
		Name: "SECURITY_RULE", Service: 2,
		DefaultAction: Action{Kind: ActionLog},
		Rules:         []Rule{rule},
	}))

	reg := NewRegistry()
	snap, err := LoadAndInstall(context.Background(), NewFileStore(path, 0), reg,
		CompileOptions{Mode: ModeOnPathInline})
	if err != nil {
		t.Fatalf("端到端装载失败: %v", err)
	}
	eng := snap.Engine("SECURITY_RULE")
	if eng == nil {
		t.Fatal("快照应提供表对应的判定引擎")
	}
	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "blocked.example"}, EvalContext{})
	if d.Verdict != ActionDeny {
		t.Fatalf("端到端判定失败: %+v", d)
	}
	if _, ok := d.EffectiveAction(); !ok {
		t.Error("端到端应产出可执行动作")
	}

	if snap.Engine("NOT_EXIST") != nil {
		t.Error("不存在的表应返回 nil 引擎")
	}
	if _, err := LoadAndInstall(context.Background(), nil, reg, CompileOptions{}); err == nil {
		t.Error("后端为 nil 应报错")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.Install([]Table{{Name: "T", Rules: []Rule{baseRule("r-1")}}},
		CompileOptions{Mode: ModeOnPathInline}, "test"); err != nil {
		t.Fatalf("装载失败: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				_, _ = reg.Install([]Table{{Name: "T", Rules: []Rule{baseRule("r-1")}}},
					CompileOptions{Mode: ModeOnPathInline}, "test")
				return
			}
			snap := reg.Current()
			if snap == nil {
				t.Error("并发读取不应看到 nil 快照")
				return
			}
			if eng := snap.Engine("T"); eng != nil {
				_ = eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "x.example"}, EvalContext{})
			}
		}(i)
	}
	wg.Wait()
}
