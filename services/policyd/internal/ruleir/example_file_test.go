package ruleir

import (
	"context"
	"path/filepath"
	"testing"
)

// TestExampleRulesFileLoads 校验随仓库提供的示例规则文件在默认部署模式（旁路）下可装载，
// 且示例中的白名单优先、排除集与早期判定三处语义符合描述。
//
// 把示例文件纳入回归的价值：示例是使用者最先复制的东西，一旦它不能装载、或其行为与
// 注释描述不符，误导成本最高（比库代码出错更难被察觉，因为使用者会以为「照抄就对了」）。
func TestExampleRulesFileLoads(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "rules.example.json")
	reg := NewRegistry()
	snap, err := LoadAndInstall(context.Background(), NewFileStore(path, 0), reg,
		CompileOptions{Mode: ModeBypass})
	if err != nil {
		t.Fatalf("示例规则文件应可在旁路模式下装载: %v", err)
	}
	if len(snap.Tables) != 2 {
		t.Fatalf("示例应含 2 张表，实际 %d", len(snap.Tables))
	}
	for _, d := range snap.Diagnostics {
		if d.Severity == SeverityError {
			t.Errorf("示例文件不应产生阻塞级诊断: %s", d.String())
		}
	}

	eng := snap.Engine("SECURITY_RULE")
	cases := []struct {
		name   string
		attrs  Attributes
		verify func(t *testing.T, d Decision)
	}{
		{
			name: "内部域走白名单（两条件 AND 均成立）",
			attrs: Attributes{
				"ATTR_SERVER_FQDN": "app.corp.internal",
				"ATTR_DST_IP":      "10.1.2.3",
			},
			verify: func(t *testing.T, d Decision) {
				if !d.Allowance || d.Verdict != ActionAllow {
					t.Fatalf("应被白名单放行，实际 %+v", d)
				}
			},
		},
		{
			name:  "恶意域名被 RST 阻断且大小写不敏感",
			attrs: Attributes{"ATTR_SERVER_FQDN": "C2.EXAMPLE"},
			verify: func(t *testing.T, d Decision) {
				if d.Verdict != ActionDeny {
					t.Fatalf("应被阻断，实际 %s", d.Verdict)
				}
				act, ok := d.EffectiveAction()
				if !ok || act.Params.ResetCount != 2 || act.Params.ResetFlags != "rst_ack" {
					t.Fatalf("动作参数未透传: %+v", act)
				}
			},
		},
		{
			name:  "排除集保护 CDN 域名",
			attrs: Attributes{"ATTR_SERVER_FQDN": "cdn.tracker.example"},
			verify: func(t *testing.T, d Decision) {
				if d.Verdict == ActionDeny {
					t.Fatal("排除集内的域名不应被阻断")
				}
				if !d.Default {
					t.Fatalf("应回落到默认动作，实际 %+v", d)
				}
			},
		},
		{
			name:  "埋点域正常阻断",
			attrs: Attributes{"ATTR_SERVER_FQDN": "ads.tracker.example"},
			verify: func(t *testing.T, d Decision) {
				if d.Verdict != ActionDeny {
					t.Fatalf("应被阻断，实际 %s", d.Verdict)
				}
			},
		},
		{
			name:  "DNS 重定向",
			attrs: Attributes{"ATTR_DNS_QNAME": "x.malware.example"},
			verify: func(t *testing.T, d Decision) {
				act, ok := d.EffectiveAction()
				if !ok || len(act.Params.DNSAnswers) == 0 || act.Params.DNSAnswers[0] != "198.51.100.9" {
					t.Fatalf("DNS 应答未透传: %+v", act)
				}
			},
		},
		{
			name: "首包载荷前缀早期判定（观察态）",
			attrs: Attributes{
				"ATTR_FIRST_PAYLOAD_C2S":     "000000016628ff",
				"ATTR_FIRST_PAYLOAD_C2S_LEN": 54,
			},
			verify: func(t *testing.T, d Decision) {
				if d.Verdict != ActionLog || d.RuleUUID != "00000000-0000-0000-0000-00000000A005" {
					t.Fatalf("应命中观察规则，实际 %+v", d)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.verify(t, eng.Evaluate(tc.attrs, EvalContext{PacketCount: 100}))
		})
	}

	// 缺少条件所依赖的属性时不成立：白名单规则要求「内部域 且 内网地址」，
	// 只给出域名不应命中 —— 这是 AND 语义的直接体现。
	if d := eng.Evaluate(Attributes{"ATTR_SERVER_FQDN": "app.corp.internal"}, EvalContext{}); d.Allowance {
		t.Fatal("多条件规则缺少属性时不应命中")
	}

	// 允许清单表：授权情报源网段必须放行，否则一次误封会连带切断自身的规则更新链路。
	allowEng := snap.Engine("ALLOWLIST")
	d := allowEng.Evaluate(Attributes{"ATTR_DST_IP": "198.51.100.7"}, EvalContext{})
	if !d.Allowance {
		t.Fatalf("授权情报源网段应被放行，实际 %+v", d)
	}

	// 停用规则仍应出现在视图中（切到在线模式后即可启用）。
	found := false
	for _, e := range snap.Tables["SECURITY_RULE"].Entries() {
		if !e.Enabled {
			found = true
		}
	}
	if !found {
		t.Error("示例中的停用规则应保留在视图内，便于切模式后启用")
	}
}
