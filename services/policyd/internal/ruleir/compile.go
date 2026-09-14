// compile.go —— 规则编译与编译期诊断。
//
// 这是本包相对 TSG/Maat 的主要增量。论文描述的工作流中，Maat 只做「加载规则表 + 扫描
// 属性」，规则的冲突、冗余与自相矛盾没有编译期检查：一张表里两条条件相同、动作相反的
// 规则谁生效，取决于加载顺序，而这在运维上表现为「加了规则但没效果」或「误封」，
// 事后只能靠人工工单逐条排查（论文 §4.1.2 记录的误封与签名失效处置正是如此）。
//
// 本文件把可以静态判定的问题提前到编译期，并在文件末尾明确写出**检测范围与未覆盖项**，
// 避免读者高估这些检查的能力。
package ruleir

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"cythsec/services/pkg/attributes"
)

// Severity 是诊断级别。
type Severity string

const (
	// SeverityError 阻塞级：存在时不应安装该表。
	SeverityError Severity = "error"
	// SeverityWarning 提示级：表可用，但存在可疑之处。
	SeverityWarning Severity = "warning"
)

// Diagnostic 是一条编译期诊断。
type Diagnostic struct {
	// 字段一律带 snake_case JSON tag：诊断会经 GET /api/v1/rule-tables/{name} 下发，
	// 缺 tag 时 Go 会按字段原名（Severity / RuleUUID）输出，与响应中其余 snake_case
	// 字段不一致，前端取 `severity` 得到 undefined —— 且不报错，只是静默为空。
	Severity Severity `json:"severity"`
	// Code 是稳定诊断码，供控制台分类与测试断言（不随文案变化）。
	Code string `json:"code"`
	// RuleUUID 定位到规则；表级问题为空。
	RuleUUID string `json:"rule_uuid,omitempty"`
	// Message 是人类可读说明，含具体取值，便于直接修复。
	Message string `json:"message"`
}

// String 输出一行式诊断文本。
func (d Diagnostic) String() string {
	where := d.RuleUUID
	if where == "" {
		where = "(表级)"
	}
	return fmt.Sprintf("[%s] %s %s: %s", d.Severity, d.Code, where, d.Message)
}

// CompileOptions 控制编译行为。
type CompileOptions struct {
	// Mode 是当前部署模式；决定哪些处置原语可用。
	Mode DeployMode
}

// CompiledTable 是编译产物：只读、已排序、已归一化。
//
// 带 JSON tag 是为「整表导出」这一用途预留：规则表要能被导出成 JSON 再原样回灌
// （导出→评审→回灌是策略变更的正常路径）。内部字段用 `json:"-"` 排除，
// 避免把编译中间态写进导出文件。
type CompiledTable struct {
	Name          string `json:"name"`
	Service       uint16 `json:"service,omitempty"`
	DefaultAction Action `json:"default_action"`
	// Rules 是全部启用规则，按 (EvaluationOrder, UUID) 稳定排序。
	Rules []*compiledRule `json:"-"`
	// AllowRules 是白名单子集，求值时先于其余规则。
	AllowRules []*compiledRule `json:"-"`
	// OtherRules 是 allow 之外的全部规则，按求值顺序排列。
	OtherRules []*compiledRule `json:"-"`
	// Diagnostics 是编译期诊断（含 error 与 warning）。
	Diagnostics []Diagnostic `json:"diagnostics"`
	// all 是全部规则的编译产物（含未启用），供 Entries 使用。
	all []*compiledRule
}

// HasErrors 表示是否存在阻塞级诊断。
func (t *CompiledTable) HasErrors() bool {
	for _, d := range t.Diagnostics {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Errors 返回全部阻塞级诊断。
func (t *CompiledTable) Errors() []Diagnostic {
	out := make([]Diagnostic, 0)
	for _, d := range t.Diagnostics {
		if d.Severity == SeverityError {
			out = append(out, d)
		}
	}
	return out
}

// Warnings 返回全部提示级诊断。
func (t *CompiledTable) Warnings() []Diagnostic {
	out := make([]Diagnostic, 0)
	for _, d := range t.Diagnostics {
		if d.Severity == SeverityWarning {
			out = append(out, d)
		}
	}
	return out
}

// AttributeNames 返回编译后规则真正引用到的属性标识（去重、字典序）。
//
// 调用方据此只计算必要属性：属性字典的 stage/cost 分级只有落到「按需计算」上才有意义。
func (t *CompiledTable) AttributeNames() []string {
	set := map[string]struct{}{}
	for _, r := range t.Rules {
		for _, a := range r.attrs {
			set[a] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compiledCondition 是预编译后的条件。
type compiledCondition struct {
	source  Condition
	attr    attributes.Def
	objects []*compiledObject
	negate  bool
}

// compiledRule 是预编译后的规则。
type compiledRule struct {
	source     Rule
	conditions []*compiledCondition
	excludes   []*compiledCondition
	action     Action
	order      float64
	attrs      []string
	// enabled 为 false 的规则已编译（以便暴露语法错误）但不参与求值。
	enabled bool
}

// RuleEntry 是编译产物中单条规则的只读视图，含未启用规则。
//
// 供控制台与审计使用：策略详情页必须能看到「文件里写了但当前未启用」的规则，
// 否则一条被停用的阻断规则会在界面上凭空消失。
type RuleEntry struct {
	Source     Rule        `json:"source"`
	Action     Action      `json:"action"`
	Enabled    bool        `json:"enabled"`
	SubActions []SubAction `json:"sub_actions"`
}

// Entries 返回全部规则的视图（含未启用规则）。
//
// 顺序：启用规则按求值顺序在前，未启用规则按文件原顺序追加在后 ——
// 前者是执行顺序，后者是待办清单，混排会让人误判求值次序。
func (t *CompiledTable) Entries() []RuleEntry {
	out := make([]RuleEntry, 0, len(t.all))
	for _, r := range t.all {
		subs := make([]SubAction, 0, len(r.action.Params.SubActions))
		subs = append(subs, r.action.Params.SubActions...)
		out = append(out, RuleEntry{
			Source:     r.source,
			Action:     r.action,
			Enabled:    r.enabled,
			SubActions: subs,
		})
	}
	return out
}

// Compile 编译规则表。无论是否存在 error 级诊断都会返回编译产物（便于控制台展示
// 「这张表哪里有问题」），由调用方依据 HasErrors 决定是否安装。
func Compile(t *Table, opts CompileOptions) *CompiledTable {
	if opts.Mode == "" {
		opts.Mode = ModeBypass
	}
	out := &CompiledTable{Name: t.Name, Service: t.Service}
	if !opts.Mode.Valid() {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{
			Severity: SeverityError, Code: "compile.mode_invalid",
			Message: fmt.Sprintf("部署模式 %q 未登记（可用：%s）", opts.Mode, joinModes(AllDeployModes())),
		})
	}

	// 表级默认动作：未声明（Kind 为空）时按「观察」处理 —— 未命中任何规则的流量
	// 不应因为「忘了配置默认动作」而被静默丢弃。
	defaultAction := t.DefaultAction
	if defaultAction.Kind == "" {
		defaultAction = Action{Kind: ActionLog}
	}
	var dias []Diagnostic
	out.DefaultAction, dias = normalizeAction(Rule{UUID: "(默认动作)", Action: defaultAction}, opts.Mode)
	out.Diagnostics = append(out.Diagnostics, dias...)

	seenUUID := map[string]int{}
	enabled := make([]*compiledRule, 0, len(t.Rules))
	all := make([]*compiledRule, 0, len(t.Rules))
	for i, r := range t.Rules {
		where := fmt.Sprintf("rules[%d]", i)
		if strings.TrimSpace(r.UUID) == "" {
			out.Diagnostics = append(out.Diagnostics, Diagnostic{
				Severity: SeverityError, Code: "rule.uuid_missing",
				Message: where + ": 规则缺少 uuid（uuid 是审计与诊断的定位键）",
			})
			continue
		}
		if prev, dup := seenUUID[r.UUID]; dup {
			out.Diagnostics = append(out.Diagnostics, Diagnostic{
				Severity: SeverityError, Code: "rule.uuid_duplicated", RuleUUID: r.UUID,
				Message: fmt.Sprintf("uuid 与 rules[%d] 重复（uuid 必须唯一，否则审计无法定位）", prev),
			})
			continue
		}
		seenUUID[r.UUID] = i

		cr, diags := compileRule(r, opts)
		out.Diagnostics = append(out.Diagnostics, diags...)
		if cr == nil {
			continue
		}
		// 未启用规则同样编译并保留视图（以便暴露语法错误、并在控制台可见），
		// 但不参与求值与冲突检测。
		cr.enabled = r.Enabled
		all = append(all, cr)
		if !r.Enabled {
			continue
		}
		enabled = append(enabled, cr)
	}

	out.Diagnostics = append(out.Diagnostics, detectConflicts(enabled)...)

	// 稳定排序：先按 evaluation_order，再按 UUID —— 同序规则的相对顺序不依赖输入次序。
	sort.SliceStable(enabled, func(i, j int) bool {
		if enabled[i].order != enabled[j].order {
			return enabled[i].order < enabled[j].order
		}
		return enabled[i].source.UUID < enabled[j].source.UUID
	})
	out.Rules = enabled
	for _, r := range enabled {
		if r.action.Kind == ActionAllow {
			out.AllowRules = append(out.AllowRules, r)
			continue
		}
		out.OtherRules = append(out.OtherRules, r)
	}

	// 视图顺序：启用规则按求值顺序，未启用规则随后。
	ordered := make([]*compiledRule, 0, len(all))
	ordered = append(ordered, enabled...)
	for _, r := range all {
		if !r.enabled {
			ordered = append(ordered, r)
		}
	}
	out.all = ordered

	out.Diagnostics = append(out.Diagnostics, detectShadowing(enabled)...)
	return out
}

// compileRule 编译单条规则。
func compileRule(r Rule, opts CompileOptions) (*compiledRule, []Diagnostic) {
	where := "规则 " + r.UUID
	diags := make([]Diagnostic, 0)

	conds, d := compileConditions(r.Conditions, where+".conditions", r.UUID)
	diags = append(diags, d...)
	excls, d := compileConditions(r.Excludes, where+".excludes", r.UUID)
	diags = append(diags, d...)

	action, d := normalizeAction(r, opts.Mode)
	diags = append(diags, d...)

	// 未启用规则不参与下发，其部署模式可用性问题降级为提示。
	//
	// 必要性：运维常见做法是「把只能在在线模式下用的规则先停在文件里，等切到在线模式
	// 再启用」。若这类规则在旁路模式下被当成阻塞级错误，整表都无法装载 —— 结果是
	// 为了保留一条待用规则而必须删掉它，反而丢失了配置意图。
	if !r.Enabled {
		for i := range diags {
			if diags[i].Code == "action.mode_unavailable" {
				diags[i].Severity = SeverityWarning
				diags[i].Message += "（规则未启用，暂不影响下发）"
			}
		}
	}

	diags = append(diags, detectSelfContradiction(r, conds)...)

	attrs := make([]string, 0, len(conds)+len(excls))
	for _, c := range conds {
		attrs = append(attrs, c.attr.ID)
	}
	for _, c := range excls {
		attrs = append(attrs, c.attr.ID)
	}

	return &compiledRule{
		source:     r,
		conditions: conds,
		excludes:   excls,
		action:     action,
		order:      r.EvaluationOrder,
		attrs:      attrs,
	}, diags
}

// compileConditions 编译条件列表，同时校验属性登记状态与对象非空。
func compileConditions(in []Condition, where, ruleUUID string) ([]*compiledCondition, []Diagnostic) {
	out := make([]*compiledCondition, 0, len(in))
	diags := make([]Diagnostic, 0)
	for i, c := range in {
		at := fmt.Sprintf("%s[%d]", where, i)
		def, ok := attributes.Lookup(c.Attribute)
		if !ok {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "attr.unknown", RuleUUID: ruleUUID,
				Message: fmt.Sprintf("%s: 属性 %q 未登记（属性必须先加入 "+
					"configs/registry/attributes.json 并重新生成绑定）", at, c.Attribute),
			})
			continue
		}
		if len(c.Objects) == 0 {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "condition.no_objects", RuleUUID: ruleUUID,
				Message: fmt.Sprintf("%s: 条件 %s 没有匹配对象（无条件成立会命中全部流量）", at, c.Attribute),
			})
			continue
		}
		cc := &compiledCondition{source: c, attr: def, negate: c.Negate}
		usable := true
		for j, obj := range c.Objects {
			co, err := compileObject(def, obj, fmt.Sprintf("%s.objects[%d]", at, j))
			if err != nil {
				diags = append(diags, Diagnostic{
					Severity: SeverityError, Code: "match.invalid_object", RuleUUID: ruleUUID,
					Message: err.Error(),
				})
				usable = false
				continue
			}
			cc.objects = append(cc.objects, co)
		}
		if usable {
			out = append(out, cc)
		}
	}
	return out, diags
}

// detectSelfContradiction 检测同一规则内的正负自相矛盾。
//
// 判据：同一属性上出现「相同对象集合」的正条件与负条件（极性不计入比较键）。
// 此时规则要求 A 且非 A 同时成立，恒为假。这是最容易写出、也最难从行为上察觉的一类
// 错误 —— 规则加载正常、日志无异常、只是永远不生效。
func detectSelfContradiction(r Rule, conds []*compiledCondition) []Diagnostic {
	out := make([]Diagnostic, 0)
	pos := map[string]bool{}
	neg := map[string]bool{}
	for _, c := range conds {
		key := c.key()
		if c.negate {
			neg[key] = true
		} else {
			pos[key] = true
		}
	}
	keys := make([]string, 0, len(pos))
	for k := range pos {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if neg[k] {
			out = append(out, Diagnostic{
				Severity: SeverityError, Code: "condition.self_contradiction", RuleUUID: r.UUID,
				Message: fmt.Sprintf("条件 %s 同时以正向与反向出现，规则恒为假", k),
			})
		}
	}
	return out
}

// detectConflicts 检测规则之间的条件等价冲突与完全重复。
//
// 判据基于「条件签名集合」的等价，因此能识别「对象顺序不同」「集合写法不同（逗号 /
// JSON 数组）」「十六进制带分隔符与不带」这类同义写法。
func detectConflicts(rules []*compiledRule) []Diagnostic {
	out := make([]Diagnostic, 0)
	bySig := map[string][]*compiledRule{}
	sigs := make([]string, 0, len(rules))
	for _, r := range rules {
		sig := r.signature()
		if _, ok := bySig[sig]; !ok {
			sigs = append(sigs, sig)
		}
		bySig[sig] = append(bySig[sig], r)
	}
	sort.Strings(sigs)

	for _, sig := range sigs {
		group := bySig[sig]
		if len(group) < 2 {
			continue
		}
		actions := map[string]bool{}
		uuids := make([]string, 0, len(group))
		for _, r := range group {
			actions[actionSignature(r.action)] = true
			uuids = append(uuids, r.source.UUID)
		}
		sort.Strings(uuids)

		if len(actions) > 1 {
			// 条件完全相同而动作不同：谁生效取决于 evaluation_order，属于必须显式裁决的
			// 情形 —— 否则「加了阻断规则却没生效」会以极高成本被排查。
			out = append(out, Diagnostic{
				Severity: SeverityError, Code: "rule.conflict", RuleUUID: uuids[0],
				Message: fmt.Sprintf("规则 %s 的条件完全相同但动作不同（%s），"+
					"需合并规则或调整条件，避免顺序决定语义",
					strings.Join(uuids, ", "), joinSet(actions)),
			})
			continue
		}
		out = append(out, Diagnostic{
			Severity: SeverityWarning, Code: "rule.duplicated", RuleUUID: uuids[0],
			Message: fmt.Sprintf("规则 %s 的条件与动作完全相同，仅保留最早求值的一条即可",
				strings.Join(uuids, ", ")),
		})
	}
	return out
}

// detectShadowing 检测被更早规则完全覆盖（永不生效）的规则。
//
// 判据：存在另一条更早求值、动作相同的规则，其条件集合是本规则条件集合的真子集 ——
// 条件之间是 AND，条件更少意味着覆盖更宽，宽规则先求值就会吃掉落在其内的全部流量。
// 这属于「顺序写错」而非语义错误，因此只报 warning。
func detectShadowing(rules []*compiledRule) []Diagnostic {
	out := make([]Diagnostic, 0)
	for i, later := range rules {
		for j, earlier := range rules {
			if i == j {
				continue
			}
			if earlier.order > later.order {
				continue
			}
			if earlier.order == later.order && earlier.source.UUID >= later.source.UUID {
				continue // 同序时以 UUID 定序，避免互为遮挡而重复告警
			}
			if actionSignature(earlier.action) != actionSignature(later.action) {
				continue
			}
			if len(earlier.conditions) >= len(later.conditions) {
				continue
			}
			if conditionsSubset(earlier.conditions, later.conditions) {
				out = append(out, Diagnostic{
					Severity: SeverityWarning, Code: "rule.shadowed", RuleUUID: later.source.UUID,
					Message: fmt.Sprintf("规则 %s 的条件被更早求值的规则 %s 完全包含且动作相同，"+
						"该规则永远不会命中", later.source.UUID, earlier.source.UUID),
				})
				break
			}
		}
	}
	return out
}

// conditionsSubset 判断 a 的每个条件是否都能在 b 中找到同签名项。
func conditionsSubset(a, b []*compiledCondition) bool {
	if len(a) == 0 {
		return false // 无条件规则视为「表级默认」，不参与覆盖性推断
	}
	set := map[string]bool{}
	for _, c := range b {
		set[c.signature()] = true
	}
	for _, c := range a {
		if !set[c.signature()] {
			return false
		}
	}
	return true
}

// key 返回条件的内容键（属性 + 对象签名，**不含极性**），用于自相矛盾检测。
func (c *compiledCondition) key() string {
	parts := make([]string, 0, len(c.objects))
	for _, o := range c.objects {
		parts = append(parts, o.signature())
	}
	sort.Strings(parts)
	return c.attr.ID + "[" + strings.Join(parts, ";") + "]"
}

// signature 返回条件签名（内容键 + 极性），用于规则等价与覆盖性判定。
func (c *compiledCondition) signature() string {
	polarity := "+"
	if c.negate {
		polarity = "-"
	}
	return polarity + c.key()
}

// objectSignature 返回匹配对象签名（方法 + 格式 + 字面量规范形式）。
func (o *compiledObject) signature() string {
	return string(o.method) + ":" + string(o.format) + ":" + o.literalKey()
}

// literalKey 把字面量归约为规范字符串，使同义写法得到同一签名。
func (o *compiledObject) literalKey() string {
	switch {
	case o.re != nil:
		return "re=" + o.re.String()
	case o.bytes != nil:
		return "bytes=" + hex.EncodeToString(o.bytes)
	case len(o.nets) > 0:
		parts := make([]string, 0, len(o.nets))
		for _, n := range o.nets {
			parts = append(parts, n.String())
		}
		sort.Strings(parts)
		return "nets=" + strings.Join(parts, ",")
	case o.netw != nil:
		return "net=" + o.netw.String()
	case o.ip != nil:
		return "ip=" + o.ip.String()
	case len(o.texts) > 0:
		parts := make([]string, len(o.texts))
		copy(parts, o.texts)
		sort.Strings(parts)
		return "set=" + strings.Join(parts, ",")
	case len(o.nums) > 0:
		parts := make([]string, 0, len(o.nums))
		for n := range o.nums {
			parts = append(parts, strconv.FormatUint(n, 10))
		}
		sort.Strings(parts)
		return "nums=" + strings.Join(parts, ",")
	case len(o.signs) > 0:
		parts := make([]string, 0, len(o.signs))
		for n := range o.signs {
			parts = append(parts, strconv.FormatInt(n, 10))
		}
		sort.Strings(parts)
		return "signs=" + strings.Join(parts, ",")
	case o.method == MethodRange:
		lo, hi := "", ""
		if o.loSet {
			lo = strconv.FormatUint(o.lo, 10)
		}
		if o.hiSet {
			hi = strconv.FormatUint(o.hi, 10)
		}
		return "range=" + lo + ".." + hi
	case o.valueTyp == attributes.ValueTypeBool:
		return "bool=" + strconv.FormatBool(o.boolv)
	case o.valueTyp == attributes.ValueTypeI64:
		return "int=" + strconv.FormatInt(o.signed, 10)
	case o.valueTyp == attributes.ValueTypeString || o.valueTyp == attributes.ValueTypeEnum:
		return "text=" + o.text
	default:
		return "num=" + strconv.FormatUint(o.num, 10)
	}
}

// signature 返回规则「条件集合 AND + 排除集 NOT」的规范签名。
func (r *compiledRule) signature() string {
	parts := make([]string, 0, len(r.conditions))
	for _, c := range r.conditions {
		parts = append(parts, c.signature())
	}
	sort.Strings(parts)
	exParts := make([]string, 0, len(r.excludes))
	for _, c := range r.excludes {
		exParts = append(exParts, c.signature())
	}
	sort.Strings(exParts)
	return "AND(" + strings.Join(parts, "&") + ")|NOT(" + strings.Join(exParts, "|") + ")"
}

// actionSignature 返回动作签名（大类 + 原语 + 关键参数），用于等价判定。
func actionSignature(a Action) string {
	subs := make([]string, 0, len(a.Params.SubActions))
	for _, s := range a.Params.SubActions {
		subs = append(subs, string(s))
	}
	sort.Strings(subs)
	p := a.Params
	return fmt.Sprintf("%s|%s|defer=%d|bps=%d|rst=%d/%s|icmp=%d|http=%d|redir=%d/%s|dns=%s|smtp=%d|sip=%d",
		a.Kind, strings.Join(subs, ","), p.DeferAfterPackets, p.ThrottleBps,
		p.ResetCount, p.ResetFlags, p.ICMPCode, p.HTTPStatusCode,
		p.RedirectCode, p.RedirectURL, strings.Join(p.DNSAnswers, ","), p.SMTPCode, p.SIPCode)
}

func joinSet(m map[string]bool) string {
	parts := make([]string, 0, len(m))
	for k := range m {
		parts = append(parts, k)
	}
	sort.Strings(parts)
	return strings.Join(parts, "/")
}

func joinModes(ms []DeployMode) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, "/")
}

// ---------------------------------------------------------------------------
// 检测范围（能力边界，明确写出来以避免过度信任）
//
// 已覆盖：
//   - 条件等价（对象顺序无关、集合写法无关、十六进制分隔符无关、网段归约）
//   - 完全重复规则
//   - 条件集合的真子集覆盖（更宽的同动作规则先求值）
//   - 单规则内正负条件自相矛盾
//   - 属性未登记、条件为空、字面量非法、方法与类型不匹配
//   - 动作参数取值域、动作-协议适配、部署模式可用性、defer 组合可疑
//
// 未覆盖（需要语义推理，本包不做，也不假装能做）：
//   - 前缀 / 后缀 / 正则之间的包含关系（如 .com 与 .com.cn 谁更宽）
//   - 网段与区间的部分重叠但不等价
//   - 跨表冲突（不同表由不同调用方使用，彼此不应互相约束）
//   - 属性取值的现实分布（属于影响面预演范畴，见 CYS-TST-015）
// ---------------------------------------------------------------------------
