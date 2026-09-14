// evaluate_test.go —— 判定求值的行为测试。
//
// 最关键的用例是白名单优先：TSG 是「先按规则拒绝、再回头检查白名单」，本包把顺序固定为
// 「白名单先于拒绝」。因此第一个用例必须证明：即使拒绝规则的 evaluation_order 更小
// （本应先求值），白名单仍然胜出。
package ruleir

import (
	"fmt"
	"strings"
	"testing"
)

func TestEvaluateWhitelistPriorityOverOrder(t *testing.T) {
	deny := baseRule("r-deny")
	deny.EvaluationOrder = 0 // 顺序更靠前
	deny.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: ".example", MatchMethod: MethodSuffix}},
	}}

	allow := baseRule("r-allow")
	allow.EvaluationOrder = 999 // 顺序最靠后
	allow.Action = Action{Kind: ActionAllow}
	allow.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: "safe.example", MatchMethod: MethodFull, Format: FormatUncase}},
	}}

	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{deny, allow}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "safe.example"}, EvalContext{})
	if d.Verdict != ActionAllow {
		t.Fatalf("白名单应优先于拒绝，实际判定 %s（来源 %s）", d.Verdict, d.RuleUUID)
	}
	if !d.Allowance {
		t.Error("Allowance 应标记本次放行来自白名单")
	}
	if _, ok := d.EffectiveAction(); ok {
		t.Error("白名单放行不应产生处置动作")
	}
	if !hasTraceContaining(d.Trace, "白名单命中") {
		t.Errorf("轨迹应说明白名单短路，实际: %v", d.Trace)
	}
}

func TestEvaluateTSGBlockedDomainCase(t *testing.T) {
	// 对齐论文 Table 2 的 Maat 规则形态：条件命中服务端 FQDN，动作 Deny + RST。
	r := Rule{
		UUID:            "...00000000A001",
		Name:            "blocked.com",
		Enabled:         true,
		EvaluationOrder: 0,
		Protocol:        "tcp",
		Conditions: []Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects:   []MatchObject{{Expression: "blocked.com", MatchMethod: MethodFull, Format: FormatUncase}},
		}},
		Action: Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubResetStream},
			ResetCount: 1,
			ResetFlags: "rst_ack",
		}},
	}
	ct := compileTable(t, &Table{Name: "SECURITY_RULE", Service: 2, Rules: []Rule{r}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "BLOCKED.com"}, EvalContext{})
	if d.Verdict != ActionDeny {
		t.Fatalf("应判定为 deny，实际 %s", d.Verdict)
	}
	act, ok := d.EffectiveAction()
	if !ok {
		t.Fatal("deny 应产生可执行动作")
	}
	if len(act.Params.SubActions) != 1 || act.Params.SubActions[0] != SubResetStream {
		t.Fatalf("动作应为 reset_stream，实际 %v", act.Params.SubActions)
	}
	if act.Params.ResetFlags != "rst_ack" || act.Params.ResetCount != 1 {
		t.Errorf("RST 参数应透传：count=%d flags=%s", act.Params.ResetCount, act.Params.ResetFlags)
	}
	if len(d.Matched) == 0 {
		t.Error("命中条件描述不应为空（可解释性要求）")
	}
}

func TestEvaluateExcludesSuppressRule(t *testing.T) {
	// 对应 TSG 为抑制误封引入的形态：命中普通条件，但落在白名单域名上时不生效。
	r := baseRule("r-exclude")
	r.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: ".example", MatchMethod: MethodSuffix, Format: FormatUncase}},
	}}
	r.Excludes = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: "safe.example", MatchMethod: MethodFull, Format: FormatUncase}},
	}}

	ct := compileTable(t, &Table{
		Name:          "T",
		Rules:         []Rule{r},
		DefaultAction: Action{Kind: ActionLog},
	}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "safe.example"}, EvalContext{})
	if d.Verdict != ActionLog {
		t.Fatalf("命中排除集时规则不应生效，应走默认动作，实际 %s", d.Verdict)
	}
	if !hasTraceContaining(d.Trace, "排除集命中") {
		t.Errorf("轨迹应说明被排除集拦下，实际: %v", d.Trace)
	}

	d = eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "evil.example"}, EvalContext{})
	if d.Verdict != ActionDeny {
		t.Fatalf("未命中排除集时应正常拒绝，实际 %s", d.Verdict)
	}
}

func TestEvaluateDeferAfterPackets(t *testing.T) {
	r := baseRule("r-defer")
	r.Protocol = "tcp"
	r.Action = Action{Kind: ActionDeny, Params: ActionParams{
		SubActions:        []SubAction{SubResetStream},
		ResetCount:        1,
		DeferAfterPackets: 5,
	}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}, DefaultAction: Action{Kind: ActionLog}},
		ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	attrs := Attributes{"ATTR_SERVER_FQDN": "blocked.example"}

	d := eng.Evaluate(attrs, EvalContext{PacketCount: 3})
	if !d.Deferred {
		t.Fatal("未达阈值时应标记为延迟")
	}
	if d.Verdict != ActionLog {
		t.Fatalf("延迟期间判定应为观察态，实际 %s", d.Verdict)
	}
	if _, ok := d.EffectiveAction(); ok {
		t.Error("延迟期间不应下发动作")
	}
	if !hasTraceContaining(d.Trace, "延迟阻断") {
		t.Errorf("轨迹应说明延迟原因，实际: %v", d.Trace)
	}

	d = eng.Evaluate(attrs, EvalContext{PacketCount: 5})
	if d.Deferred {
		t.Fatal("达到阈值后应生效")
	}
	if d.Verdict != ActionDeny {
		t.Fatalf("达到阈值后应拒绝，实际 %s", d.Verdict)
	}
	if _, ok := d.EffectiveAction(); !ok {
		t.Error("达到阈值后应下发动作")
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	first := baseRule("r-first")
	first.EvaluationOrder = 10
	first.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: ".example", MatchMethod: MethodSuffix}},
	}}

	second := baseRule("r-second")
	second.EvaluationOrder = 20
	second.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: "blocked.example", MatchMethod: MethodFull}},
	}}

	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{first, second}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})
	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "blocked.example"}, EvalContext{})
	if d.RuleUUID != "r-first" {
		t.Fatalf("应命中先求值的规则，实际 %s", d.RuleUUID)
	}
}

func TestEvaluateDataErrorIsRecordedAndDoesNotAbort(t *testing.T) {
	r := baseRule("r-type")
	r.Conditions = []Condition{{
		Attribute: "ATTR_DST_PORT",
		Objects:   []MatchObject{{Expression: "443"}},
	}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}, DefaultAction: Action{Kind: ActionLog}},
		ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	// 属性值类型与字典冲突：既不能静默忽略，也不能中断整条判定链。
	d := eng.Evaluate(Attributes{"ATTR_DST_PORT": "not-a-port"}, EvalContext{})
	if len(d.Errors) == 0 {
		t.Fatal("值类型冲突必须记录到 Errors，否则「规则不生效」无从排查")
	}
	if d.Verdict != ActionLog {
		t.Fatalf("该条件应视为不成立并继续后续规则，实际 %s", d.Verdict)
	}
}

func TestEvaluateNegateWithMissingAttribute(t *testing.T) {
	r := baseRule("r-negate")
	r.Conditions = []Condition{{
		Attribute: "ATTR_IOC_HIT",
		Negate:    true,
		Objects:   []MatchObject{{Expression: "ioc-1", MatchMethod: MethodSet}},
	}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	// 属性缺失 + 负条件：语义上「没有命中该 IOC」成立，故规则命中。
	d := eng.Evaluate(Attributes{}, EvalContext{})
	if d.Verdict != ActionDeny {
		t.Fatalf("负条件在属性缺失时应成立，实际 %s", d.Verdict)
	}
	// 轨迹必须同时说明「属性缺失」与「这是否定条件」两件事：只写其中一件，
	// 复盘的人就无法判断是数据没采上来还是规则写反了。
	if !hasTraceContaining(d.Trace, "属性缺失") {
		t.Errorf("轨迹应说明属性缺失，实际: %v", d.Trace)
	}
	if !hasTraceContaining(d.Trace, "否定条件") {
		t.Errorf("轨迹应标明否定条件，实际: %v", d.Trace)
	}
}

func TestEvaluateTraceDescribesExpectationWhenNotMatched(t *testing.T) {
	// 未命中的条件必须在轨迹里写出「本来要求匹配什么」。
	// 这是排查「规则为什么没生效」的唯一线索：只写结果不写期望，
	// 轨迹就退化为一串「不成立」，等于没有轨迹。
	r := baseRule("r-expect")
	r.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects: []MatchObject{
			{Expression: "a.example", MatchMethod: MethodFull, Format: FormatUncase},
			{Expression: ".b.example", MatchMethod: MethodSuffix, Format: FormatUncase},
		},
	}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "other.example"}, EvalContext{})
	var line string
	for _, l := range d.Trace {
		if strings.Contains(l, "ATTR_SERVER_FQDN") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("轨迹应包含条件行，实际: %v", d.Trace)
	}
	if !strings.Contains(line, "未匹配任何对象") || !strings.Contains(line, "期望") {
		t.Fatalf("未命中的轨迹行应写出期望匹配的对象，实际: %q", line)
	}
	if !strings.Contains(line, "a.example") || !strings.Contains(line, ".b.example") {
		t.Errorf("期望对象应逐个列出（便于核对规则内容），实际: %q", line)
	}
	// 反面约束：轨迹行不得出现「条件 X:  → 」这样的空细节形态。
	if strings.Contains(line, ":  →") {
		t.Errorf("轨迹行不应出现空细节，实际: %q", line)
	}

	// 对象集过大时只展示前若干个，避免单条规则撑满 TraceLimit。
	many := baseRule("r-many")
	objs := make([]MatchObject, 0, 50)
	for i := 0; i < 50; i++ {
		objs = append(objs, MatchObject{
			Expression: fmt.Sprintf("x%d.example", i), MatchMethod: MethodFull, Format: FormatUncase})
	}
	many.Conditions = []Condition{{Attribute: "ATTR_SERVER_FQDN", Objects: objs}}
	ct = compileTable(t, &Table{Name: "T", Rules: []Rule{many}}, ModeOnPathInline)
	eng = NewEngine(ct, EngineOptions{})
	d = eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "other.example"}, EvalContext{})
	for _, l := range d.Trace {
		if strings.Contains(l, "ATTR_SERVER_FQDN") {
			line = l
		}
	}
	if !strings.Contains(line, "共 50 个对象") {
		t.Errorf("对象过多时应给出总数提示，实际: %q", line)
	}
	if strings.Count(line, ".example") > maxExpectDescriptions {
		t.Errorf("期望对象条数应受上限约束，实际: %q", line)
	}
}

func TestEvaluateTraceSeparatesEvalErrorFromNoMatch(t *testing.T) {
	// 值类型与字典冲突时，轨迹必须写明是「数据问题」而不是「值不匹配」：
	// 两者的处置动作完全不同（前者改采集，后者改规则）。
	r := baseRule("r-err")
	r.Conditions = []Condition{{
		Attribute: "ATTR_DST_PORT",
		Objects:   []MatchObject{{Expression: "443", MatchMethod: MethodFull}},
	}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{"ATTR_DST_PORT": "not-a-number"}, EvalContext{})
	if len(d.Errors) == 0 {
		t.Fatal("类型冲突应记入 Errors")
	}
	if !hasTraceContaining(d.Trace, "求值出错") {
		t.Errorf("轨迹应标明求值出错，实际: %v", d.Trace)
	}
	if !hasTraceContaining(d.Trace, "未参与判定") {
		t.Errorf("轨迹应说明该条件未参与判定，实际: %v", d.Trace)
	}
}

func TestEvaluateThrottleAction(t *testing.T) {
	r := baseRule("r-throttle")
	r.Action = Action{Kind: ActionThrottle, Params: ActionParams{
		SubActions: []SubAction{SubThrottleSession}, ThrottleBps: 65536}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "blocked.example"}, EvalContext{})
	act, ok := d.EffectiveAction()
	if !ok {
		t.Fatal("限速应产生可执行动作")
	}
	if act.Kind != ActionThrottle || act.Params.ThrottleBps != 65536 {
		t.Fatalf("限速参数未透传: %+v", act)
	}
}

func TestEvaluateTraceLimit(t *testing.T) {
	rules := make([]Rule, 0, 8)
	for i := 0; i < 8; i++ {
		rr := baseRule("r-miss-" + string(rune('a'+i)))
		rr.EvaluationOrder = float64(i)
		rr.Conditions = []Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects:   []MatchObject{{Expression: "never-" + string(rune('a'+i)) + ".example", MatchMethod: MethodFull}},
		}}
		rules = append(rules, rr)
	}
	ct := compileTable(t, &Table{Name: "T", Rules: rules, DefaultAction: Action{Kind: ActionLog}},
		ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{TraceLimit: 3})

	d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "other.example"}, EvalContext{})
	if len(d.Trace) > 3 {
		t.Fatalf("轨迹应受上限约束，实际 %d 条", len(d.Trace))
	}
}

func TestEvaluateIsStateless(t *testing.T) {
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{baseRule("r-1")}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})
	attrs := Attributes{"ATTR_SERVER_FQDN": "blocked.example"}

	first := eng.Evaluate(attrs, EvalContext{})
	second := eng.Evaluate(attrs, EvalContext{})
	if first.Verdict != second.Verdict || first.RuleUUID != second.RuleUUID {
		t.Fatalf("同一输入两次判定结果不一致：%v vs %v", first, second)
	}
	if len(first.Trace) != len(second.Trace) {
		t.Fatalf("轨迹长度应一致：%d vs %d", len(first.Trace), len(second.Trace))
	}
}

func TestEvaluateNilTableEngine(t *testing.T) {
	eng := NewEngine(nil, EngineOptions{})
	d := eng.Evaluate(Attributes{}, EvalContext{})
	if d.Verdict != ActionLog || !d.Default {
		t.Fatalf("空表应安全回落为观察态，实际 %+v", d)
	}
}

func TestDecisionStringAndDefault(t *testing.T) {
	ct := compileTable(t, &Table{Name: "SECURITY_RULE", Rules: []Rule{baseRule("r-1")},
		DefaultAction: Action{Kind: ActionLog}}, ModeOnPathInline)
	eng := NewEngine(ct, EngineOptions{})

	d := eng.Evaluate(Attributes{}, EvalContext{})
	if !d.Default {
		t.Fatal("未命中任何规则时应标记 Default")
	}
	s := d.String()
	if !strings.Contains(s, "SECURITY_RULE") || !strings.Contains(s, string(ActionLog)) {
		t.Fatalf("判定摘要信息不全: %s", s)
	}

	d = eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "blocked.example"}, EvalContext{})
	if !strings.Contains(d.String(), "r-1") {
		t.Fatalf("判定摘要应含规则标识: %s", d.String())
	}
}

func hasTraceContaining(trace []string, sub string) bool {
	for _, l := range trace {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
