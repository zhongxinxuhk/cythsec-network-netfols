// rules_test.go —— 规则表与属性字典端点的行为测试。
//
// 端点同样遵循「控制面不执行处置」的原则：这里断言的核心是「试算返回判定与轨迹，
// 但不下发任何动作」，以及「未登记属性被显式回显」——后者是规则试算可信的前提。
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"cythsec/services/pkg/controlplane"
	"cythsec/services/pkg/metrics"
	"cythsec/services/policyd/internal/ruleir"
)

// newRuleTestServer 构造带规则表的测试服务。
func newRuleTestServer(t *testing.T, mode ruleir.DeployMode, tables ...ruleir.Table) http.Handler {
	t.Helper()
	reg := ruleir.NewRegistry()
	if len(tables) > 0 {
		if _, err := reg.Install(tables, ruleir.CompileOptions{Mode: mode}, "test"); err != nil {
			t.Fatalf("装载测试规则失败: %v", err)
		}
	}

	var ruleCount *metrics.Gauge
	rt, err := controlplane.NewRuntime(controlplane.ServerConfig{
		Service:        ServiceName,
		LogLevel:       "error",
		LogFormat:      "json",
		MetricsEnabled: true,
		Logger:         discardLogger(),
		RegisterMetrics: func(mreg *metrics.Registry) error {
			ruleCount = NewRuleCountGauge(mreg)
			return nil
		},
	}, func(mux *http.ServeMux) {
		RegisterRoutes(mux, ServerOptions{
			RuleRegistry: reg,
			DeployMode:   mode,
		})
		_ = ruleCount
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt.Handler
}

// sampleTable 返回一张含白名单、阻断与观察规则的表。
func sampleTable(t *testing.T) ruleir.Table {
	t.Helper()
	deny := ruleir.Rule{
		UUID:            "uuid-deny-1",
		Name:            "阻断恶意域名",
		Enabled:         true,
		EvaluationOrder: 20,
		Protocol:        "tcp",
		Conditions: []ruleir.Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects: []ruleir.MatchObject{{
				Expression: "blocked.example", MatchMethod: ruleir.MethodFull, Format: ruleir.FormatUncase,
			}},
		}},
		Action: ruleir.Action{Kind: ruleir.ActionDeny, Params: ruleir.ActionParams{
			SubActions: []ruleir.SubAction{ruleir.SubResetStream},
			ResetCount: 1,
			ResetFlags: "rst_ack",
			// 故意设置延迟：用于验证试算端点的 deferred 语义
			DeferAfterPackets: 10,
		}},
	}
	allow := ruleir.Rule{
		UUID:            "uuid-allow-1",
		Name:            "放行白名单域",
		Enabled:         true,
		EvaluationOrder: 99,
		Conditions: []ruleir.Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects: []ruleir.MatchObject{{
				Expression: "safe.example", MatchMethod: ruleir.MethodFull, Format: ruleir.FormatUncase,
			}},
		}},
		Action: ruleir.Action{Kind: ruleir.ActionAllow},
	}
	return ruleir.Table{
		Name:          "SECURITY_RULE",
		Service:       2,
		DefaultAction: ruleir.Action{Kind: ruleir.ActionLog},
		Rules:         []ruleir.Rule{deny, allow},
	}
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) (*httptest.ResponseRecorder, envelope) {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var env envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("响应不是合法 JSON: %v\n%s", err, rec.Body.String())
	}
	return rec, env
}

func TestListRuleTables(t *testing.T) {
	h := newRuleTestServer(t, ruleir.ModeOnPathInline, sampleTable(t))

	rec, env := doJSON(t, h, http.MethodGet, "/api/v1/rule-tables", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Revision   uint64 `json:"revision"`
		Checksum   string `json:"checksum"`
		DeployMode string `json:"deploy_mode"`
		Tables     []struct {
			Name       string   `json:"name"`
			Rules      int      `json:"rules"`
			AllowRules int      `json:"allow_rules"`
			Attributes []string `json:"attributes"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(env.Data, &out); err != nil {
		t.Fatalf("解析 data 失败: %v", err)
	}
	if out.Revision != 1 || len(out.Checksum) != 64 {
		t.Errorf("版本信息不完整: revision=%d checksum=%q", out.Revision, out.Checksum)
	}
	if out.DeployMode != string(ruleir.ModeOnPathInline) {
		t.Errorf("部署模式未回显: %s", out.DeployMode)
	}
	if len(out.Tables) != 1 {
		t.Fatalf("应有 1 张表，实际 %d", len(out.Tables))
	}
	tbl := out.Tables[0]
	if tbl.Name != "SECURITY_RULE" || tbl.Rules != 2 || tbl.AllowRules != 1 {
		t.Errorf("表摘要不符: %+v", tbl)
	}
	if len(tbl.Attributes) == 0 || tbl.Attributes[0] != "ATTR_SERVER_FQDN" {
		t.Errorf("应列出表引用的属性: %v", tbl.Attributes)
	}
}

func TestGetRuleTable(t *testing.T) {
	h := newRuleTestServer(t, ruleir.ModeOnPathInline, sampleTable(t))

	rec, env := doJSON(t, h, http.MethodGet, "/api/v1/rule-tables/SECURITY_RULE", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Name  string `json:"name"`
		Rules []struct {
			UUID       string   `json:"uuid"`
			Enabled    bool     `json:"enabled"`
			SubActions []string `json:"sub_actions"`
		} `json:"rules"`
		Diagnostics []ruleir.Diagnostic `json:"diagnostics"`
	}
	if err := json.Unmarshal(env.Data, &out); err != nil {
		t.Fatalf("解析 data 失败: %v", err)
	}
	if len(out.Rules) != 2 {
		t.Fatalf("应返回 2 条规则，实际 %d", len(out.Rules))
	}
	// 求值顺序：阻断(20) 在 白名单(99) 之前，但视图顺序按求值顺序排列
	if out.Rules[0].UUID != "uuid-deny-1" {
		t.Errorf("规则顺序应按求值顺序: %+v", out.Rules)
	}
	if len(out.Rules[0].SubActions) != 1 || out.Rules[0].SubActions[0] != "reset_stream" {
		t.Errorf("应回显归一化后的处置原语: %v", out.Rules[0].SubActions)
	}

	rec, env = doJSON(t, h, http.MethodGet, "/api/v1/rule-tables/NOT_EXIST", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的表应返回 404，实际 %d", rec.Code)
	}
	if env.Code != 4004 {
		t.Errorf("业务码应为 4004，实际 %d", env.Code)
	}
}

func TestEvaluateRuleTableDryRun(t *testing.T) {
	h := newRuleTestServer(t, ruleir.ModeOnPathInline, sampleTable(t))

	type evalOut struct {
		Verdict           string   `json:"verdict"`
		RuleUUID          string   `json:"rule_uuid"`
		Allowance         bool     `json:"allowance"`
		Deferred          bool     `json:"deferred"`
		SubActions        []string `json:"sub_actions"`
		WouldExecute      bool     `json:"would_execute"`
		Trace             []string `json:"trace"`
		UnknownAttributes []string `json:"unknown_attributes"`
		DryRun            bool     `json:"dry_run"`
	}

	t.Run("阻断且达到阈值后下发动作", func(t *testing.T) {
		rec, env := doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/SECURITY_RULE/evaluate",
			`{"attributes":{"ATTR_SERVER_FQDN":"BLOCKED.example"},"packet_count":50}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
		}
		var out evalOut
		if err := json.Unmarshal(env.Data, &out); err != nil {
			t.Fatalf("解析 data 失败: %v", err)
		}
		if out.Verdict != "deny" || out.RuleUUID != "uuid-deny-1" {
			t.Fatalf("判定不符: %+v", out)
		}
		if !out.WouldExecute || len(out.SubActions) != 1 || out.SubActions[0] != "reset_stream" {
			t.Errorf("应给出将执行的动作: %+v", out)
		}
		if !out.DryRun {
			t.Error("dry_run 必须为 true")
		}
		if len(out.Trace) == 0 {
			t.Error("应返回求值轨迹")
		}
	})

	t.Run("未达延迟阈值时不下发动作", func(t *testing.T) {
		_, env := doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/SECURITY_RULE/evaluate",
			`{"attributes":{"ATTR_SERVER_FQDN":"blocked.example"},"packet_count":3}`)
		var out evalOut
		if err := json.Unmarshal(env.Data, &out); err != nil {
			t.Fatalf("解析 data 失败: %v", err)
		}
		if !out.Deferred || out.WouldExecute {
			t.Fatalf("延迟期不应执行动作: %+v", out)
		}
	})

	t.Run("白名单优先于拒绝", func(t *testing.T) {
		_, env := doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/SECURITY_RULE/evaluate",
			`{"attributes":{"ATTR_SERVER_FQDN":"safe.example"}}`)
		var out evalOut
		if err := json.Unmarshal(env.Data, &out); err != nil {
			t.Fatalf("解析 data 失败: %v", err)
		}
		if !out.Allowance || out.WouldExecute {
			t.Fatalf("白名单放行不应产生动作: %+v", out)
		}
	})

	t.Run("未登记属性被显式回显", func(t *testing.T) {
		// 带 packet_count 是为了跨过示例规则的延迟阈值：否则判定会降级为观察态，
		// 无法区分「属性没被采纳」与「延迟未到期」两种完全不同的原因。
		_, env := doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/SECURITY_RULE/evaluate",
			`{"attributes":{"ATTR_TYPO_FQDN":"x.example","ATTR_SERVER_FQDN":"blocked.example"},"packet_count":50}`)
		var out evalOut
		if err := json.Unmarshal(env.Data, &out); err != nil {
			t.Fatalf("解析 data 失败: %v", err)
		}
		if len(out.UnknownAttributes) != 1 || out.UnknownAttributes[0] != "ATTR_TYPO_FQDN" {
			t.Fatalf("拼错的属性名必须回显，否则试算结果会被误信: %+v", out)
		}
		if out.Verdict != "deny" {
			t.Errorf("已登记属性仍应参与判定: %+v", out)
		}
	})

	t.Run("请求体非法返回 400", func(t *testing.T) {
		rec, env := doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/SECURITY_RULE/evaluate",
			`{"attributes":{},"unknown_field":1}`)
		if rec.Code != http.StatusBadRequest || env.Code != 4001 {
			t.Fatalf("未知字段应返回 400/4001，实际 %d/%d：%s", rec.Code, env.Code, rec.Body.String())
		}
		rec, _ = doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/SECURITY_RULE/evaluate", ``)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("空请求体应返回 400，实际 %d", rec.Code)
		}
	})
}

func TestAttributesEndpoint(t *testing.T) {
	h := newRuleTestServer(t, ruleir.ModeOnPathInline, sampleTable(t))

	rec, env := doJSON(t, h, http.MethodGet, "/api/v1/attributes", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		RegistryVersion uint32   `json:"registry_version"`
		Count           int      `json:"count"`
		Formats         []string `json:"formats"`
		ActionKinds     []string `json:"action_kinds"`
		DeployModes     []string `json:"deploy_modes"`
		Types           []struct {
			Name          string   `json:"name"`
			Methods       []string `json:"methods"`
			DefaultMethod string   `json:"default_method"`
			DefaultFormat string   `json:"default_format"`
		} `json:"types"`
		SubActions []struct {
			Name             string          `json:"name"`
			RequiresProtocol string          `json:"requires_protocol"`
			AvailableIn      map[string]bool `json:"available_in"`
		} `json:"sub_actions"`
		Attributes []struct {
			ID   string `json:"ID"`
			Type string `json:"Type"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal(env.Data, &out); err != nil {
		t.Fatalf("解析 data 失败: %v", err)
	}
	if out.RegistryVersion == 0 || out.Count == 0 || len(out.Attributes) != out.Count {
		t.Errorf("属性字典信息不完整: version=%d count=%d attrs=%d",
			out.RegistryVersion, out.Count, len(out.Attributes))
	}
	if len(out.Formats) == 0 || len(out.ActionKinds) == 0 || len(out.DeployModes) == 0 {
		t.Error("规则编写所需的枚举值应全部下发，避免控制台硬编码造成漂移")
	}

	// 每种类型都要给出可用匹配方法与默认值（控制台据此渲染下拉并禁用非法组合）
	for _, tp := range out.Types {
		if len(tp.Methods) == 0 || tp.DefaultMethod == "" || tp.DefaultFormat == "" {
			t.Errorf("类型 %s 元数据不全: %+v", tp.Name, tp)
		}
	}

	// 处置原语必须给出跨部署模式的可用性：旁路下丢包/限速应为 false。
	found := false
	for _, sa := range out.SubActions {
		if sa.Name == string(ruleir.SubDropStream) {
			found = true
			if sa.AvailableIn[string(ruleir.ModeBypass)] {
				t.Error("旁路模式下 drop_stream 不应标记为可用")
			}
			if !sa.AvailableIn[string(ruleir.ModeOnPathInline)] {
				t.Error("在线模式下 drop_stream 应可用")
			}
		}
		if sa.Name == string(ruleir.SubResetStream) && sa.RequiresProtocol != "tcp" {
			t.Errorf("reset_stream 应声明需要 tcp 上下文，实际 %q", sa.RequiresProtocol)
		}
	}
	if !found {
		t.Error("响应应包含 drop_stream 原语")
	}
}

func TestRuleEndpointsWithoutRegistry(t *testing.T) {
	// 未配置规则表时，端点应明确告知「未装载」，而不是 404 让人误以为表名写错。
	h := newRuleTestServer(t, ruleir.ModeBypass)

	for _, path := range []string{"/api/v1/rule-tables", "/api/v1/rule-tables/ANY"} {
		rec, env := doJSON(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s 应返回 503，实际 %d", path, rec.Code)
		}
		if !strings.Contains(env.Error, "rule_tables_file") {
			t.Errorf("%s 的错误信息应指出配置项: %s", path, env.Error)
		}
	}

	rec, _ := doJSON(t, h, http.MethodPost, "/api/v1/rule-tables/ANY/evaluate", `{"attributes":{}}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("试算端点也应返回 503，实际 %d", rec.Code)
	}

	// 属性字典不依赖规则表，应始终可用
	rec, _ = doJSON(t, h, http.MethodGet, "/api/v1/attributes", "")
	if rec.Code != http.StatusOK {
		t.Errorf("属性字典端点应始终可用，实际 %d", rec.Code)
	}
}

// TestDiagnosticsUseSnakeCaseKeys 锁定诊断的线上字段名。
//
// 这个用例存在的唯一理由是：缺 JSON tag 时 Go 会按字段原名输出
// （Severity / RuleUUID），与响应中其余 snake_case 字段混排。前端取 `severity`
// 得到 undefined —— 不报错、不崩，只是一片空白，是最难发现的一类契约漂移。
func TestDiagnosticsUseSnakeCaseKeys(t *testing.T) {
	// 构造一条必然产生诊断的规则：旁路模式下使用 drop_stream。
	//
	// 刻意设为 Enabled: false —— 严重度策略是「启用规则用了不可用原语 = 阻塞错误，
	// 停用规则 = 提示」。前者会拒绝装载，后者才允许装载并带诊断输出。
	r := ruleir.Rule{
		UUID:            "uuid-diag-1",
		Enabled:         false,
		EvaluationOrder: 10,
		Conditions: []ruleir.Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects: []ruleir.MatchObject{{
				Expression: "x.example", MatchMethod: ruleir.MethodFull, Format: ruleir.FormatUncase,
			}},
		}},
		Action: ruleir.Action{Kind: ruleir.ActionDeny, Params: ruleir.ActionParams{
			SubActions: []ruleir.SubAction{ruleir.SubDropStream},
		}},
	}
	h := newRuleTestServer(t, ruleir.ModeBypass,
		ruleir.Table{Name: "SECURITY_RULE", Rules: []ruleir.Rule{r}})

	rec, env := doJSON(t, h, http.MethodGet, "/api/v1/rule-tables/SECURITY_RULE", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}

	var raw struct {
		Diagnostics []map[string]any `json:"diagnostics"`
	}
	if err := json.Unmarshal(env.Data, &raw); err != nil {
		t.Fatalf("解析 data 失败: %v", err)
	}
	if len(raw.Diagnostics) == 0 {
		t.Fatal("旁路模式下 drop_stream 应产生诊断，实际无")
	}
	for _, d := range raw.Diagnostics {
		for _, k := range []string{"severity", "code", "message"} {
			if _, ok := d[k]; !ok {
				t.Errorf("诊断缺少 snake_case 字段 %q，实际键=%v", k, mapKeys(d))
			}
		}
		// 反向断言：不得出现 Go 字段原名。
		for _, bad := range []string{"Severity", "RuleUUID", "Message", "Code"} {
			if _, ok := d[bad]; ok {
				t.Errorf("诊断泄漏了 Go 字段原名 %q（应 snake_case），实际键=%v", bad, mapKeys(d))
			}
		}
	}
}

// mapKeys 返回 map 的键（排序后），用于错误信息。
func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
