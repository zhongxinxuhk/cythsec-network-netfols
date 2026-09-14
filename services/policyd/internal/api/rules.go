// Package api rules.go —— 规则表与属性字典的只读控制面端点。
//
// 端点设计原则：**控制面不执行处置**。这里只暴露「规则怎么写的、判定会得出什么」，
// 真正的报文处置属于数据面。因此最有价值的一个端点不是查询，而是试算：
//
//	POST /api/v1/rule-tables/{name}/evaluate
//
// 它接收一组属性值，返回判定结果与完整求值轨迹，但不产生任何副作用。这对应本方案
// 里的离线回放与影响面预演能力（CYS-TST-015）：先在历史流量上试算，再决定是否上线，
// 而不是上线后靠投诉发现误封。
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/attributes"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/policyd/internal/ruleir"
)

// maxEvaluateBodyBytes 是试算请求体上限。
//
// 限流的理由不是安全，而是可用性：试算接口要遍历全部规则，一个超大请求体会让单次
// 判定耗时不可控。64 KiB 足以容纳数百个属性键值。
const maxEvaluateBodyBytes = 64 << 10

// registerRuleRoutes 注册规则与属性相关路由。
//
// 由 RegisterRoutes 调用；未配置规则表（Registry 为 nil）时只注册属性字典与
// 「未配置」提示端点，避免控制台拿到 404 后无从判断是「没配置」还是「表名错了」。
func registerRuleRoutes(mux *http.ServeMux, opts ServerOptions) {
	controlplane.Handle(mux, "GET /api/v1/rule-tables", listRuleTables(opts))
	controlplane.Handle(mux, "GET /api/v1/rule-tables/{name}", getRuleTable(opts))
	controlplane.Handle(mux, "POST /api/v1/rule-tables/{name}/evaluate", evaluateRuleTable(opts))
	controlplane.Handle(mux, "GET /api/v1/attributes", listAttributes())
}

// ruleTableSummary 是规则表列表项。
type ruleTableSummary struct {
	Name       string `json:"name"`
	Service    uint16 `json:"service,omitempty"`
	Rules      int    `json:"rules"`
	AllowRules int    `json:"allow_rules"`
	// Attributes 是本表引用到的属性标识，供调用方按需计算属性。
	Attributes   []string `json:"attributes"`
	ErrorCount   int      `json:"error_count"`
	WarningCount int      `json:"warning_count"`
}

// ruleTablesResponse 是 GET /api/v1/rule-tables 的响应体。
type ruleTablesResponse struct {
	Revision     uint64             `json:"revision"`
	Checksum     string             `json:"checksum"`
	Source       string             `json:"source"`
	LoadedAt     string             `json:"loaded_at"`
	DeployMode   string             `json:"deploy_mode"`
	Tables       []ruleTableSummary `json:"tables"`
	ErrorCount   int                `json:"error_count"`
	WarningCount int                `json:"warning_count"`
}

// listRuleTables 返回当前快照的表级摘要（不含具体规则，避免响应过大）。
func listRuleTables(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := currentSnapshot(opts)
		if snap == nil {
			apiresp.Err(w, r, http.StatusServiceUnavailable, apiresp.CodeNotFound,
				"未装载规则表：请在配置中设置 rule_tables_file")
			return
		}

		out := ruleTablesResponse{
			Revision:   snap.Version.Revision,
			Checksum:   snap.Version.Checksum,
			Source:     snap.Version.Source,
			LoadedAt:   snap.Version.LoadedAt.Format(time.RFC3339),
			DeployMode: string(opts.DeployMode),
		}
		for _, name := range snap.TableNames() {
			ct := snap.Tables[name]
			out.Tables = append(out.Tables, ruleTableSummary{
				Name:         ct.Name,
				Service:      ct.Service,
				Rules:        len(ct.Rules),
				AllowRules:   len(ct.AllowRules),
				Attributes:   ct.AttributeNames(),
				ErrorCount:   len(ct.Errors()),
				WarningCount: len(ct.Warnings()),
			})
			out.ErrorCount += len(ct.Errors())
			out.WarningCount += len(ct.Warnings())
		}
		if out.Tables == nil {
			out.Tables = []ruleTableSummary{}
		}
		apiresp.JSON(w, r, http.StatusOK, out)
	}
}

// ruleView 是规则的对外视图（含编译后的归一化动作）。
type ruleView struct {
	UUID            string             `json:"uuid"`
	Name            string             `json:"name,omitempty"`
	Enabled         bool               `json:"enabled"`
	EvaluationOrder float64            `json:"evaluation_order"`
	Protocol        string             `json:"protocol,omitempty"`
	Description     string             `json:"description,omitempty"`
	Conditions      []ruleir.Condition `json:"conditions,omitempty"`
	Excludes        []ruleir.Condition `json:"excludes,omitempty"`
	Action          ruleir.Action      `json:"action"`
	// SubActions 是归一化后实际会执行的处置原语（如 deny 未指定时补出的 drop_stream）。
	SubActions []string `json:"sub_actions"`
}

// ruleTableDetail 是 GET /api/v1/rule-tables/{name} 的响应体。
type ruleTableDetail struct {
	Name          string              `json:"name"`
	Service       uint16              `json:"service,omitempty"`
	DefaultAction ruleir.Action       `json:"default_action"`
	Attributes    []string            `json:"attributes"`
	Rules         []ruleView          `json:"rules"`
	Diagnostics   []ruleir.Diagnostic `json:"diagnostics"`
	DeployMode    string              `json:"deploy_mode"`
}

// getRuleTable 返回单表的完整视图（含诊断）。
func getRuleTable(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		snap := currentSnapshot(opts)
		if snap == nil {
			apiresp.Err(w, r, http.StatusServiceUnavailable, apiresp.CodeNotFound,
				"未装载规则表：请在配置中设置 rule_tables_file")
			return
		}
		ct, ok := snap.Tables[name]
		if !ok {
			apiresp.Err(w, r, http.StatusNotFound, apiresp.CodeNotFound,
				"规则表不存在: "+name)
			return
		}

		out := ruleTableDetail{
			Name:          ct.Name,
			Service:       ct.Service,
			DefaultAction: ct.DefaultAction,
			Attributes:    ct.AttributeNames(),
			Diagnostics:   ct.Diagnostics,
			DeployMode:    string(opts.DeployMode),
		}
		for _, entry := range ct.Entries() {
			src := entry.Source
			subs := make([]string, 0, len(entry.SubActions))
			for _, s := range entry.SubActions {
				subs = append(subs, string(s))
			}
			out.Rules = append(out.Rules, ruleView{
				UUID:            src.UUID,
				Name:            src.Name,
				Enabled:         entry.Enabled,
				EvaluationOrder: src.EvaluationOrder,
				Protocol:        src.Protocol,
				Description:     src.Description,
				Conditions:      src.Conditions,
				Excludes:        src.Excludes,
				Action:          entry.Action,
				SubActions:      subs,
			})
		}
		if out.Rules == nil {
			out.Rules = []ruleView{}
		}
		if out.Diagnostics == nil {
			out.Diagnostics = []ruleir.Diagnostic{}
		}
		apiresp.JSON(w, r, http.StatusOK, out)
	}
}

// evaluateRequest 是试算请求体。
type evaluateRequest struct {
	// Attributes 是属性标识到值的映射，值类型约定见 ruleir.Attributes。
	Attributes map[string]any `json:"attributes"`
	// PacketCount 用于 defer_after_packets 语义；缺省为 0。
	PacketCount uint64 `json:"packet_count,omitempty"`
}

// evaluateResponse 是试算结果。
type evaluateResponse struct {
	Verdict    string   `json:"verdict"`
	RuleUUID   string   `json:"rule_uuid,omitempty"`
	RuleName   string   `json:"rule_name,omitempty"`
	Allowance  bool     `json:"allowance"`
	Deferred   bool     `json:"deferred"`
	Default    bool     `json:"default_action"`
	SubActions []string `json:"sub_actions"`
	// WouldExecute 表示「若这是真实流量，是否会下发处置」。始终为 false 的
	// 判定不会产生任何副作用。
	WouldExecute bool     `json:"would_execute"`
	Matched      []string `json:"matched"`
	Trace        []string `json:"trace"`
	// Errors 是求值中的数据问题（属性值类型与字典冲突等）。
	Errors []string `json:"errors"`
	// UnknownAttributes 是请求里未登记的属性标识 —— 显式回显，避免调用方
	// 因拼错属性名而误判「规则没生效」。
	UnknownAttributes []string `json:"unknown_attributes"`
	DeployMode        string   `json:"deploy_mode"`
	// DryRun 恒为 true，语义是「本端点只计算不下发」。
	DryRun bool `json:"dry_run"`
}

// evaluateRuleTable 对一组属性试算判定结果（无副作用）。
func evaluateRuleTable(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		snap := currentSnapshot(opts)
		if snap == nil {
			apiresp.Err(w, r, http.StatusServiceUnavailable, apiresp.CodeNotFound,
				"未装载规则表：请在配置中设置 rule_tables_file")
			return
		}
		eng := snap.Engine(name)
		if eng == nil {
			apiresp.Err(w, r, http.StatusNotFound, apiresp.CodeNotFound,
				"规则表不存在: "+name)
			return
		}

		var req evaluateRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			apiresp.Err(w, r, http.StatusBadRequest, apiresp.CodeBadRequest, err.Error())
			return
		}

		attrs := ruleir.Attributes{}
		unknown := make([]string, 0)
		for k, v := range req.Attributes {
			if _, ok := attributes.Lookup(k); !ok {
				unknown = append(unknown, k)
				continue
			}
			attrs[k] = v
		}
		sort.Strings(unknown)

		d := eng.Evaluate(attrs, ruleir.EvalContext{PacketCount: req.PacketCount})
		subs := make([]string, 0, len(d.Action.Params.SubActions))
		for _, s := range d.Action.Params.SubActions {
			subs = append(subs, string(s))
		}
		_, wouldExecute := d.EffectiveAction()

		apiresp.JSON(w, r, http.StatusOK, evaluateResponse{
			Verdict:           string(d.Verdict),
			RuleUUID:          d.RuleUUID,
			RuleName:          d.RuleName,
			Allowance:         d.Allowance,
			Deferred:          d.Deferred,
			Default:           d.Default,
			SubActions:        subs,
			WouldExecute:      wouldExecute,
			Matched:           d.Matched,
			Trace:             d.Trace,
			Errors:            d.Errors,
			UnknownAttributes: unknown,
			DeployMode:        string(opts.DeployMode),
			DryRun:            true,
		})
	}
}

// attributeTypeView 是值类型及其可用匹配方法。
type attributeTypeView struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Methods       []string `json:"methods"`
	DefaultMethod string   `json:"default_method"`
	DefaultFormat string   `json:"default_format"`
}

// subActionView 是处置原语及其跨部署模式的可用性。
type subActionView struct {
	Name             string          `json:"name"`
	RequiresProtocol string          `json:"requires_protocol,omitempty"`
	AvailableIn      map[string]bool `json:"available_in"`
}

// attributesResponse 是属性字典与规则编写元数据的响应体。
type attributesResponse struct {
	RegistryVersion uint32              `json:"registry_version"`
	Count           int                 `json:"count"`
	Formats         []string            `json:"formats"`
	ActionKinds     []string            `json:"action_kinds"`
	DeployModes     []string            `json:"deploy_modes"`
	Types           []attributeTypeView `json:"types"`
	SubActions      []subActionView     `json:"sub_actions"`
	Attributes      []attributes.Def    `json:"attributes"`
}

// listAttributes 暴露属性字典与规则编写所需的枚举值。
//
// 存在的意义是让控制台不必硬编码任何枚举：属性、匹配方法、格式、动作原语及其
// 部署模式可用性全部由服务端下发。硬编码的代价是两侧漂移，而漂移的表现是
// 「界面上能选的组合其实是非法组合」。
func listAttributes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := attributesResponse{
			RegistryVersion: attributes.RegistryVersion,
			Count:           attributes.Count(),
			Attributes:      attributes.All(),
		}
		for _, f := range ruleir.AllFormats() {
			out.Formats = append(out.Formats, string(f))
		}
		for _, k := range ruleir.AllActionKinds() {
			out.ActionKinds = append(out.ActionKinds, string(k))
		}
		modes := ruleir.AllDeployModes()
		for _, m := range modes {
			out.DeployModes = append(out.DeployModes, string(m))
		}

		typeNames := attributeTypeNames()
		for _, t := range typeNames {
			v := attributeTypeView{
				Name:          string(t),
				Description:   t.Description(),
				DefaultMethod: string(ruleir.DefaultMethod(t)),
				DefaultFormat: string(ruleir.DefaultFormat(t)),
			}
			for _, m := range ruleir.MethodsFor(t) {
				v.Methods = append(v.Methods, string(m))
			}
			out.Types = append(out.Types, v)
		}

		for _, sa := range ruleir.SubActions() {
			v := subActionView{
				Name:             string(sa),
				RequiresProtocol: ruleir.RequiredProtocol(sa),
				AvailableIn:      map[string]bool{},
			}
			for _, m := range modes {
				v.AvailableIn[string(m)] = ruleir.SubActionAvailable(sa, m)
			}
			out.SubActions = append(out.SubActions, v)
		}
		apiresp.JSON(w, r, http.StatusOK, out)
	}
}

// attributeTypeNames 收集当前字典实际使用的值类型（去重、按名排序）。
func attributeTypeNames() []attributes.ValueType {
	seen := map[attributes.ValueType]bool{}
	for _, def := range attributes.All() {
		seen[def.Type] = true
	}
	out := make([]attributes.ValueType, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// currentSnapshot 返回当前快照；未配置规则表时为 nil。
func currentSnapshot(opts ServerOptions) *ruleir.Snapshot {
	if opts.RuleRegistry == nil {
		return nil
	}
	return opts.RuleRegistry.Current()
}

// decodeJSONBody 严格解析请求体：限制大小、禁止未知字段、要求单一 JSON 对象。
//
// 与策略文件的解析口径保持一致（见 policy.LoadFile）：字段名写错要立即失败，
// 否则试算结果会因「属性名拼错被忽略」而与真实判定不符 —— 试算的意义正在于可信。
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxEvaluateBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("请求体超过 %d 字节上限", maxEvaluateBodyBytes)
		}
		if errors.Is(err, io.EOF) {
			return errors.New("请求体为空")
		}
		return fmt.Errorf("解析请求体失败: %w", err)
	}
	if dec.More() {
		return errors.New("请求体只能包含一个 JSON 对象")
	}
	return nil
}
