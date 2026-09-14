// action_test.go —— 处置动作模型的行为测试。
//
// 重点覆盖三类 TSG 缺失的编译期校验：参数取值域、动作-协议适配、部署模式可用性。
package ruleir

import (
	"strings"
	"testing"
)

func TestDenyWithoutPrimitiveDefaultsToDropStream(t *testing.T) {
	r := baseRule("r-deny")
	r.Action = Action{Kind: ActionDeny} // 未指定处置原语

	diags := compileSingleRule(t, r, ModeOnPathInline)
	if !hasCode(diags, "action.deny_defaulted") {
		t.Fatalf("期望给出归一化提示，实际诊断: %v", diagnoseCodes(diags))
	}
	if hasCode(diags, "action.mode_unavailable") {
		t.Error("归一化后的 drop_stream 在在线模式下应可用")
	}

	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	got := ct.Rules[0].action.Params.SubActions
	if len(got) != 1 || got[0] != SubDropStream {
		t.Fatalf("deny 未指定原语时应归一化为 drop_stream，实际 %v", got)
	}
}

func TestActionKindConsistency(t *testing.T) {
	cases := []struct {
		name string
		act  Action
		code string
	}{
		{"白名单不应带原语", Action{Kind: ActionAllow, Params: ActionParams{SubActions: []SubAction{SubDropStream}}}, "action.allow_has_subaction"},
		{"观察态不应带原语", Action{Kind: ActionLog, Params: ActionParams{SubActions: []SubAction{SubResetStream}}}, "action.log_has_subaction"},
		{"限速必须带限速原语", Action{Kind: ActionThrottle}, "action.throttle_without_primitive"},
		{"重定向必须带重定向原语", Action{Kind: ActionRedirect, Params: ActionParams{SubActions: []SubAction{SubDropStream}}}, "action.redirect_without_primitive"},
		{"未登记的动作大类", Action{Kind: "blackhole"}, "action.unknown_kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := baseRule("r-kind")
			r.Action = tc.act
			diags := compileSingleRule(t, r, ModeOnPathInline)
			if !hasCode(diags, tc.code) {
				t.Fatalf("期望诊断 %s，实际 %v", tc.code, diagnoseCodes(diags))
			}
		})
	}
}

func TestActionParamValidation(t *testing.T) {
	base := func() Rule {
		r := baseRule("r-param")
		r.Conditions = []Condition{{
			Attribute: "ATTR_DNS_QNAME",
			Objects:   []MatchObject{{Expression: "blocked.example"}},
		}}
		return r
	}

	cases := []struct {
		name   string
		params ActionParams
		wantIn string
	}{
		{"RST 个数越界", ActionParams{SubActions: []SubAction{SubResetStream}, ResetCount: 4}, "reset_count=4"},
		{"RST 标志非法", ActionParams{SubActions: []SubAction{SubResetStream}, ResetFlags: "syn"}, "reset_flags"},
		{"ICMP 码非法", ActionParams{SubActions: []SubAction{SubInjectICMPUnreachable}, ICMPCode: 42}, "icmp_code=42"},
		{"HTTP 状态码非法", ActionParams{SubActions: []SubAction{SubInjectHTTPStatus}, HTTPStatusCode: 500}, "http_status_code=500"},
		{"重定向码非法", ActionParams{SubActions: []SubAction{SubInjectHTTPRedirect}, RedirectCode: 301, RedirectURL: "https://sink.example/"}, "redirect_code=301"},
		{"重定向 URL 非绝对", ActionParams{SubActions: []SubAction{SubInjectHTTPRedirect}, RedirectCode: 302, RedirectURL: "/sink"}, "不是绝对 URL"},
		{"DNS 应答为空", ActionParams{SubActions: []SubAction{SubInjectDNSRedirect}}, "dns_answers 为空"},
		{"DNS 应答非 IP", ActionParams{SubActions: []SubAction{SubInjectDNSRedirect}, DNSAnswers: []string{"not-an-ip"}}, "不是合法 IP"},
		{"SMTP 码非法", ActionParams{SubActions: []SubAction{SubInjectSMTPReply}, SMTPCode: 250}, "smtp_code=250"},
		{"SIP 码非法", ActionParams{SubActions: []SubAction{SubInjectSIPReply}, SIPCode: 200}, "sip_code=200"},
		{"限速阈值为零", ActionParams{SubActions: []SubAction{SubThrottleSession}}, "throttle_bps=0"},
		{"未登记的原语", ActionParams{SubActions: []SubAction{"tamper_payload"}}, "tamper_payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			r.Action = Action{Kind: ActionDeny, Params: tc.params}
			diags := compileSingleRule(t, r, ModeOnPathInline)
			msg := messageOf(diags, "action.param_invalid")
			if msg == "" {
				diags = append(diags, compileSingleRule(t, r, ModeOnPathInline)...)
			}
			all := joinDiagnostics(diags)
			if !strings.Contains(all, tc.wantIn) {
				t.Fatalf("诊断未包含 %q，实际:\n  %s", tc.wantIn, all)
			}
		})
	}
}

func TestActionProtocolAdaptation(t *testing.T) {
	t.Run("HTTP 注入缺少协议上下文", func(t *testing.T) {
		r := baseRule("r-proto-1")
		r.Conditions = []Condition{{
			Attribute: "ATTR_DST_PORT", // 通用属性，推断不出协议
			Objects:   []MatchObject{{Expression: "80"}},
		}}
		r.Action = Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubInjectHTTPStatus}, HTTPStatusCode: 403}}
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if !hasCode(diags, "action.protocol_missing") {
			t.Fatalf("期望 action.protocol_missing，实际 %v", diagnoseCodes(diags))
		}
	})

	t.Run("HTTP 注入与 TLS 条件冲突", func(t *testing.T) {
		r := baseRule("r-proto-2")
		r.Conditions = []Condition{{
			Attribute: "ATTR_TLS_SNI",
			Objects:   []MatchObject{{Expression: "blocked.example"}},
		}}
		r.Action = Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubInjectHTTPStatus}, HTTPStatusCode: 403}}
		diags := compileSingleRule(t, r, ModeOnPathInline)
		msg := messageOf(diags, "action.protocol_mismatch")
		if msg == "" || !strings.Contains(msg, "tls") {
			t.Fatalf("期望协议冲突诊断并指出推断协议 tls，实际:\n  %s", joinDiagnostics(diags))
		}
	})

	t.Run("HTTP 注入与 HTTP 条件相容", func(t *testing.T) {
		r := baseRule("r-proto-3")
		r.Conditions = []Condition{{
			Attribute: "ATTR_HTTP_HOST",
			Objects:   []MatchObject{{Expression: "blocked.example"}},
		}}
		r.Action = Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubInjectHTTPStatus}, HTTPStatusCode: 403}}
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if hasCode(diags, "action.protocol_mismatch") || hasCode(diags, "action.protocol_missing") {
			t.Fatalf("相容组合不应报协议问题: %s", joinDiagnostics(diags))
		}
	})

	t.Run("显式声明协议与动作冲突", func(t *testing.T) {
		r := baseRule("r-proto-4")
		r.Protocol = "tls"
		r.Action = Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubInjectHTTPStatus}, HTTPStatusCode: 403}}
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if !hasCode(diags, "action.protocol_mismatch") {
			t.Fatalf("期望 action.protocol_mismatch，实际 %v", diagnoseCodes(diags))
		}
	})

	t.Run("DNS 重定向需要 DNS 上下文", func(t *testing.T) {
		r := baseRule("r-proto-5")
		r.Conditions = []Condition{{
			Attribute: "ATTR_DNS_QNAME",
			Objects:   []MatchObject{{Expression: "blocked.example"}},
		}}
		r.Action = Action{Kind: ActionRedirect, Params: ActionParams{
			SubActions: []SubAction{SubInjectDNSRedirect}, DNSAnswers: []string{"198.51.100.9"}}}
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if hasCode(diags, "action.protocol_mismatch") || hasCode(diags, "action.protocol_missing") {
			t.Fatalf("DNS 条件 + DNS 原语应相容: %s", joinDiagnostics(diags))
		}
	})
}

func TestDeployModeAvailability(t *testing.T) {
	cases := []struct {
		sub  SubAction
		mode DeployMode
		want bool
	}{
		{SubDropStream, ModeOnPathInline, true},
		{SubDropStream, ModeOnPathTransparent, true},
		{SubDropStream, ModePcap, true},
		{SubDropStream, ModeBypass, false},
		{SubDropCurrentPacket, ModeBypass, false},
		{SubThrottleSession, ModeBypass, false},
		{SubThrottlePacket, ModeBypass, false},
		{SubResetStream, ModeBypass, true},
		{SubInjectHTTPStatus, ModeBypass, true},
		{SubInjectDNSRedirect, ModeBypass, true},
		{"no_such_primitive", ModeOnPathInline, false},
	}
	for _, tc := range cases {
		if got := SubActionAvailable(tc.sub, tc.mode); got != tc.want {
			t.Errorf("SubActionAvailable(%s, %s) = %v，期望 %v", tc.sub, tc.mode, got, tc.want)
		}
	}

	t.Run("旁路模式下丢包动作被拒绝", func(t *testing.T) {
		r := baseRule("r-mode")
		diags := compileSingleRule(t, r, ModeBypass) // baseRule 使用 drop_stream
		msg := messageOf(diags, "action.mode_unavailable")
		if msg == "" {
			t.Fatalf("期望 action.mode_unavailable，实际 %v", diagnoseCodes(diags))
		}
		if !strings.Contains(msg, "drop_stream") {
			t.Errorf("诊断应指出具体原语，实际: %s", msg)
		}
	})

	t.Run("旁路模式下注入动作可用", func(t *testing.T) {
		r := baseRule("r-mode-2")
		r.Action = Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubResetStream}, ResetCount: 2, ResetFlags: "rst_ack"}}
		diags := compileSingleRule(t, r, ModeBypass)
		if hasCode(diags, "action.mode_unavailable") {
			t.Fatalf("旁路应允许注入 RST: %s", joinDiagnostics(diags))
		}
	})
}

func TestDeferValidation(t *testing.T) {
	t.Run("延迟阻断为负", func(t *testing.T) {
		r := baseRule("r-defer-1")
		r.Action.Params.DeferAfterPackets = -1
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if msg := messageOf(diags, "action.param_invalid"); !strings.Contains(msg, "不能为负") {
			t.Fatalf("期望参数错误，实际 %v", diagnoseCodes(diags))
		}
	})

	t.Run("延迟与丢流组合给出提示", func(t *testing.T) {
		r := baseRule("r-defer-2")
		r.Action.Params.DeferAfterPackets = 5
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if !hasCode(diags, "action.combination_useless") {
			t.Fatalf("期望组合提示，实际 %v", diagnoseCodes(diags))
		}
	})

	t.Run("延迟与 RST 组合无提示", func(t *testing.T) {
		r := baseRule("r-defer-3")
		r.Action = Action{Kind: ActionDeny, Params: ActionParams{
			SubActions: []SubAction{SubResetStream}, ResetCount: 1, DeferAfterPackets: 5}}
		diags := compileSingleRule(t, r, ModeOnPathInline)
		if hasCode(diags, "action.combination_useless") {
			t.Fatal("RST 与延迟阻断组合是常见用法，不应告警")
		}
	})
}

func TestDuplicatePrimitiveDeduplicated(t *testing.T) {
	r := baseRule("r-dup")
	r.Protocol = "tcp" // RST 需要 TCP 上下文；条件未引用协议属性时需显式声明
	r.Action = Action{Kind: ActionDeny, Params: ActionParams{
		SubActions: []SubAction{SubResetStream, SubResetStream, SubInjectICMPUnreachable}}}
	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{r}}, ModeOnPathInline)
	got := ct.Rules[0].action.Params.SubActions
	if len(got) != 2 {
		t.Fatalf("重复原语应被去重，实际 %v", got)
	}
}

func TestDisabledRuleDowngradesModeUnavailable(t *testing.T) {
	// 停用一条只能在在线模式下使用的规则，不应阻塞整表装载。
	r := baseRule("r-parked") // drop_stream 在旁路下不可用
	r.Enabled = false

	ct := Compile(&Table{Name: "T", Rules: []Rule{r}}, CompileOptions{Mode: ModeBypass})
	if ct.HasErrors() {
		t.Fatalf("未启用规则的部署模式问题不应阻塞装载: %s", joinDiagnostics(ct.Errors()))
	}
	if !hasCode(ct.Diagnostics, "action.mode_unavailable") {
		t.Fatal("降级为提示后仍应在诊断中出现，以便提醒切模式时需要复核")
	}
	for _, d := range ct.Diagnostics {
		if d.Code == "action.mode_unavailable" && d.Severity != SeverityWarning {
			t.Fatalf("严重级别应为 warning，实际 %s", d.Severity)
		}
	}
	// 规则仍应出现在视图里（停用不等于隐藏）
	entries := ct.Entries()
	if len(entries) != 1 || entries[0].Enabled {
		t.Fatalf("停用规则应保留在视图中且标记为未启用: %+v", entries)
	}

	// 启用之后必须回到阻塞级
	r.Enabled = true
	ct = Compile(&Table{Name: "T", Rules: []Rule{r}}, CompileOptions{Mode: ModeBypass})
	if !ct.HasErrors() {
		t.Fatal("启用后旁路模式下的丢包动作必须阻塞装载")
	}
}

func TestEntriesIncludesEnabledInEvaluationOrder(t *testing.T) {
	early := baseRule("r-early")
	early.EvaluationOrder = 5
	early.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: "early.example", MatchMethod: MethodFull}},
	}}
	late := baseRule("r-late")
	late.EvaluationOrder = 50
	late.Conditions = []Condition{{
		Attribute: "ATTR_SERVER_FQDN",
		Objects:   []MatchObject{{Expression: "late.example", MatchMethod: MethodFull}},
	}}
	parked := baseRule("r-parked")
	parked.Enabled = false

	ct := compileTable(t, &Table{Name: "T", Rules: []Rule{late, early, parked}}, ModeOnPathInline)
	entries := ct.Entries()
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Source.UUID)
	}
	want := []string{"r-early", "r-late", "r-parked"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("视图顺序错误: got %v want %v", got, want)
		}
	}
	if entries[2].Enabled {
		t.Error("最后一条应为未启用规则")
	}
}

func TestSubActionsRegistryIsComplete(t *testing.T) {
	// 每个已登记原语都必须有可用性与协议判定结果（哪怕是「与协议无关」）。
	for _, sub := range SubActions() {
		if !sub.Valid() {
			t.Errorf("原语 %s 未通过 Valid()", sub)
		}
		_ = requiredProtocol(sub)
		_ = SubActionAvailable(sub, ModeOnPathInline)
	}
	if len(SubActions()) != 11 {
		t.Errorf("已登记原语数量为 %d，与设计（11 类）不符 —— "+
			"改动原语集合时请同步更新文档与测试", len(SubActions()))
	}
}
