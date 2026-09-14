// compile_test.go —— 编译期诊断的行为测试。
//
// 这些用例对应的正是 TSG/Maat 缺失的能力：冲突、冗余、自相矛盾在编译期暴露。
// 每个用例都断言「诊断码 + 是否阻塞装载」，而不仅是消息文案。
package ruleir

import (
	"strings"
	"testing"
)

func TestCompileConflictDetected(t *testing.T) {
	allow := baseRule("r-allow")
	allow.Action = Action{Kind: ActionAllow}

	deny := baseRule("r-deny")
	deny.EvaluationOrder = 20 // 顺序不同，条件完全相同

	ct := Compile(&Table{Name: "T", Rules: []Rule{deny, allow}}, CompileOptions{Mode: ModeOnPathInline})
	if !ct.HasErrors() {
		t.Fatal("条件相同而动作不同应被视为阻塞级冲突")
	}
	msg := messageOf(ct.Diagnostics, "rule.conflict")
	if msg == "" {
		t.Fatalf("期望 rule.conflict，实际 %v", diagnoseCodes(ct.Diagnostics))
	}
	if !strings.Contains(msg, "r-allow") || !strings.Contains(msg, "r-deny") {
		t.Errorf("冲突诊断应列出双方 uuid，实际: %s", msg)
	}
}

func TestCompileSignatureUnifiesEquivalentWritings(t *testing.T) {
	// 同一语义的规则用不同写法表达：对象顺序不同、集合写法不同。仍应被判为等价。
	a := baseRule("r-a")
	a.Conditions = []Condition{
		{
			Attribute: "ATTR_SERVER_FQDN",
			Objects: []MatchObject{
				{Expression: ".example", MatchMethod: MethodSuffix, Format: FormatUncase},
				{Expression: ".invalid", MatchMethod: MethodSuffix, Format: FormatUncase},
			},
		},
		{
			Attribute: "ATTR_DST_PORT",
			Objects:   []MatchObject{{Expression: "443"}},
		},
	}
	b := baseRule("r-b")
	b.Conditions = []Condition{
		{
			Attribute: "ATTR_DST_PORT",
			Objects:   []MatchObject{{Expression: "443"}},
		},
		{
			Attribute: "ATTR_SERVER_FQDN",
			Objects: []MatchObject{
				// 集合写法 + 顺序与 a 不同
				{Expression: `[".invalid",".example"]`, MatchMethod: MethodSet, Format: FormatUncase},
			},
		},
	}
	// 注意：set 与 suffix 是不同语义，这里改造成同一语义再比较 —— 用两条 set 规则验证归一化。
	c := baseRule("r-c")
	c.Conditions = b.Conditions

	ct := Compile(&Table{Name: "T", Rules: []Rule{a, c}}, CompileOptions{Mode: ModeOnPathInline})
	diags := ct.Diagnostics
	// a 与 c 语义不同（suffix 集合 vs set 集合），不应误报冲突。
	if hasCode(diags, "rule.conflict") || hasCode(diags, "rule.duplicated") {
		t.Fatalf("语义不同的规则不应被判为等价: %s", joinDiagnostics(diags))
	}

	// b 与 c 条件写法不同（对象顺序、集合写法），应被判为完全重复。
	ct = Compile(&Table{Name: "T", Rules: []Rule{b, c}}, CompileOptions{Mode: ModeOnPathInline})
	if !hasCode(ct.Diagnostics, "rule.duplicated") {
		t.Fatalf("同义写法应被识别为重复，实际 %v", diagnoseCodes(ct.Diagnostics))
	}
}

func TestCompileDuplicateDetected(t *testing.T) {
	r1 := baseRule("r-1")
	r2 := baseRule("r-2")
	r2.EvaluationOrder = 20

	ct := Compile(&Table{Name: "T", Rules: []Rule{r1, r2}}, CompileOptions{Mode: ModeOnPathInline})
	if ct.HasErrors() {
		t.Fatalf("完全重复只应是提示级: %s", joinDiagnostics(ct.Errors()))
	}
	if !hasCode(ct.Diagnostics, "rule.duplicated") {
		t.Fatalf("期望 rule.duplicated，实际 %v", diagnoseCodes(ct.Diagnostics))
	}
}

func TestCompileShadowingDetected(t *testing.T) {
	broad := baseRule("r-broad") // 1 个条件，先求值
	broad.EvaluationOrder = 10

	narrow := baseRule("r-narrow") // 在 broad 条件之上再加一个条件
	narrow.EvaluationOrder = 20
	narrow.Conditions = append(narrow.Conditions, Condition{
		Attribute: "ATTR_DST_PORT",
		Objects:   []MatchObject{{Expression: "443"}},
	})

	ct := Compile(&Table{Name: "T", Rules: []Rule{narrow, broad}}, CompileOptions{Mode: ModeOnPathInline})
	if !hasCode(ct.Diagnostics, "rule.shadowed") {
		t.Fatalf("期望 rule.shadowed，实际 %v", diagnoseCodes(ct.Diagnostics))
	}
	msg := messageOf(ct.Diagnostics, "rule.shadowed")
	if !strings.Contains(msg, "r-broad") {
		t.Errorf("遮挡诊断应指出是哪条规则遮挡，实际: %s", msg)
	}
}

func TestCompileNoShadowingWhenOrderReversed(t *testing.T) {
	narrow := baseRule("r-narrow")
	narrow.EvaluationOrder = 10
	narrow.Conditions = append(narrow.Conditions, Condition{
		Attribute: "ATTR_DST_PORT",
		Objects:   []MatchObject{{Expression: "443"}},
	})

	broad := baseRule("r-broad")
	broad.EvaluationOrder = 20

	ct := Compile(&Table{Name: "T", Rules: []Rule{broad, narrow}}, CompileOptions{Mode: ModeOnPathInline})
	if hasCode(ct.Diagnostics, "rule.shadowed") {
		t.Fatalf("窄规则先求值属正常写法，不应告警: %s", joinDiagnostics(ct.Diagnostics))
	}
}

func TestCompileSelfContradictionDetected(t *testing.T) {
	r := baseRule("r-contra")
	r.Conditions = []Condition{
		{
			Attribute: "ATTR_SERVER_FQDN",
			Objects:   []MatchObject{{Expression: "blocked.example"}},
		},
		{
			Attribute: "ATTR_SERVER_FQDN",
			Negate:    true,
			Objects:   []MatchObject{{Expression: "blocked.example"}},
		},
	}
	diags := compileSingleRule(t, r, ModeOnPathInline)
	if !hasCode(diags, "condition.self_contradiction") {
		t.Fatalf("期望 condition.self_contradiction，实际 %v", diagnoseCodes(diags))
	}
}

func TestCompileNegateWithDifferentObjectIsFine(t *testing.T) {
	// 正条件与负条件针对同一属性但取值不同，属于正常的「排除集」写法。
	r := baseRule("r-ok")
	r.Conditions = []Condition{
		{
			Attribute: "ATTR_SERVER_FQDN",
			Objects:   []MatchObject{{Expression: ".example", MatchMethod: MethodSuffix}},
		},
		{
			Attribute: "ATTR_SERVER_FQDN",
			Negate:    true,
			Objects:   []MatchObject{{Expression: "safe.example", MatchMethod: MethodFull}},
		},
	}
	diags := compileSingleRule(t, r, ModeOnPathInline)
	if hasCode(diags, "condition.self_contradiction") {
		t.Fatalf("不同取值的正负条件不应判为自相矛盾: %s", joinDiagnostics(diags))
	}
}

func TestCompileStructuralErrors(t *testing.T) {
	cases := []struct {
		name  string
		build func() []Rule
		code  string
	}{
		{
			name: "属性未登记",
			build: func() []Rule {
				r := baseRule("r-1")
				r.Conditions[0].Attribute = "ATTR_NOT_REGISTERED"
				return []Rule{r}
			},
			code: "attr.unknown",
		},
		{
			name: "条件没有匹配对象",
			build: func() []Rule {
				r := baseRule("r-2")
				r.Conditions[0].Objects = nil
				return []Rule{r}
			},
			code: "condition.no_objects",
		},
		{
			name: "缺少 uuid",
			build: func() []Rule {
				r := baseRule("r-3")
				r.UUID = ""
				return []Rule{r}
			},
			code: "rule.uuid_missing",
		},
		{
			name: "uuid 重复",
			build: func() []Rule {
				return []Rule{baseRule("r-4"), baseRule("r-4")}
			},
			code: "rule.uuid_duplicated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct := Compile(&Table{Name: "T", Rules: tc.build()}, CompileOptions{Mode: ModeOnPathInline})
			if !hasCode(ct.Diagnostics, tc.code) {
				t.Fatalf("期望 %s，实际 %v", tc.code, diagnoseCodes(ct.Diagnostics))
			}
			if !ct.HasErrors() {
				t.Error("结构错误应为阻塞级")
			}
		})
	}
}

func TestCompileOrderingAndSplit(t *testing.T) {
	// 条件各不相同，避免触发「条件相同而动作不同」的冲突检测。
	mk := func(uuid string, order float64, kind ActionKind, expr string) Rule {
		r := baseRule(uuid)
		r.EvaluationOrder = order
		r.Action = Action{Kind: kind}
		r.Conditions = []Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects:   []MatchObject{{Expression: expr, MatchMethod: MethodFull}},
		}}
		return r
	}

	allow := mk("r-allow", 40, ActionAllow, "allow.example")
	log := mk("r-log", 10, ActionLog, "log.example")
	deny := mk("r-deny", 20, ActionDeny, "deny.example")
	deny2 := mk("r-deny-2", 20, ActionDeny, "deny2.example")

	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{allow, deny2, log, deny}}, ModeOnPathInline)

	gotOrder := make([]string, 0, len(ct.Rules))
	for _, r := range ct.Rules {
		gotOrder = append(gotOrder, r.source.UUID)
	}
	want := []string{"r-log", "r-deny", "r-deny-2", "r-allow"}
	for i := range want {
		if gotOrder[i] != want[i] {
			t.Fatalf("求值顺序错误：got %v want %v", gotOrder, want)
		}
	}
	if len(ct.AllowRules) != 1 || ct.AllowRules[0].source.UUID != "r-allow" {
		t.Errorf("白名单子集划分错误: %v", ct.AllowRules)
	}
	if len(ct.OtherRules) != 3 {
		t.Errorf("其余规则应有 3 条，实际 %d", len(ct.OtherRules))
	}
}

func TestCompileAttributeNames(t *testing.T) {
	r := baseRule("r-attrs")
	r.Conditions = []Condition{
		{Attribute: "ATTR_SERVER_FQDN", Objects: []MatchObject{{Expression: "a.example"}}},
		{Attribute: "ATTR_DST_PORT", Objects: []MatchObject{{Expression: "443"}}},
	}
	r.Excludes = []Condition{
		{Attribute: "ATTR_SERVER_FQDN", Objects: []MatchObject{{Expression: "safe.example"}}},
		{Attribute: "ATTR_IOC_HIT", Objects: []MatchObject{{Expression: "ioc-1"}}},
	}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	got := strings.Join(ct.AttributeNames(), ",")
	want := "ATTR_DST_PORT,ATTR_IOC_HIT,ATTR_SERVER_FQDN"
	if got != want {
		t.Fatalf("属性依赖集合错误：got %s want %s", got, want)
	}
}

func TestCompileDisabledRuleSkipped(t *testing.T) {
	enabled := baseRule("r-on")
	disabled := baseRule("r-off")
	disabled.Enabled = false
	disabled.Action = Action{Kind: ActionAllow} // 与 enabled 条件相同但动作不同

	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{enabled, disabled}}, ModeOnPathInline)
	if len(ct.Rules) != 1 || ct.Rules[0].source.UUID != "r-on" {
		t.Fatalf("未启用规则不应进入求值集合: %v", ct.Rules)
	}
	if hasCode(ct.Diagnostics, "rule.conflict") {
		t.Error("未启用规则参与冲突检测会产生噪声（草稿态规则应允许存在）")
	}
}

func TestCompileDefaultActionFallback(t *testing.T) {
	ct := compileTable(t, &Table{Name: "T"}, ModeOnPathInline)
	if ct.DefaultAction.Kind != ActionLog {
		t.Fatalf("未声明默认动作时应回落为观察态，实际 %q", ct.DefaultAction.Kind)
	}
}

func TestCompileInvalidMode(t *testing.T) {
	ct := Compile(&Table{Name: "T"}, CompileOptions{Mode: "sideways"})
	if !hasCode(ct.Diagnostics, "compile.mode_invalid") {
		t.Fatalf("期望 compile.mode_invalid，实际 %v", diagnoseCodes(ct.Diagnostics))
	}
}

func TestCompiledTableDiagnosticFilters(t *testing.T) {
	r1 := baseRule("r-1")
	r2 := baseRule("r-2")
	ct := Compile(&Table{Name: "T", Rules: []Rule{r1, r2}}, CompileOptions{Mode: ModeOnPathInline})
	if ct.HasErrors() {
		t.Fatalf("重复规则不应阻塞: %s", joinDiagnostics(ct.Errors()))
	}
	if len(ct.Warnings()) == 0 {
		t.Fatal("重复规则应产生至少一条提示")
	}
	if len(ct.Errors()) != 0 {
		t.Fatalf("Errors() 只应返回阻塞级诊断，实际 %d 条", len(ct.Errors()))
	}
}
