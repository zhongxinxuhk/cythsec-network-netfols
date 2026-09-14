// evaluate.go —— 判定求值引擎。
//
// 与 TSG 的关键差异是**求值顺序**。论文描述的工作流中，多个判定源各自发布结果、由防火墙
// 汇总后逐条扫描 Maat 表；白名单是误封投诉之后补上的「保护机制」（论文 §4.1.2、Figure 3），
// 即：先按规则判定为拒绝，再回头检查是否应放行。
//
// 本包把顺序反过来，并把它固定为引擎语义而非配置项：
//
//	第 1 步：求值全部 allow 规则（白名单）。命中即放行，不再看其余规则。
//	第 2 步：按 evaluation_order 求值其余规则（deny / log / throttle / redirect）。
//	第 3 步：未命中任何规则，执行表级默认动作。
//
// 理由是可用性而非偏好：安全设备最贵的故障是误封（把正常业务切断），而白名单是唯一
// 能在判定链路内直接压制误封的机制。先拒绝再补救意味着每一次误封都已经生效过一次。
//
// 本文件的第二个职责是**可解释**：TSG 的多路径聚合是「各自发布 + 硬聚合」，命中后无法
// 回答「为什么命中」。Decision 里带完整的条件级轨迹（Trace）与数据错误（Errors），
// 使判定结果可被审计与复盘。
package ruleir

import (
	"fmt"
	"strings"
)

// EvalContext 是一次判定的上下文。
type EvalContext struct {
	// PacketCount 是当前会话已处理的报文数，用于 defer_after_packets（延迟阻断）。
	// 由调用方提供而非引擎自持，使求值保持无状态、可重放。
	PacketCount uint64
}

// Decision 是一次判定结果。
//
// 字段带 snake_case JSON tag：判定结果要进审计日志与试算响应，两者都是跨进程契约，
// 缺 tag 会让 Go 字段原名泄漏到线上格式里。
//
// 说明：本包中的 *Options / *Context 类结构（CompileOptions、EngineOptions、EvalContext）
// 刻意不加 tag —— 它们是进程内的调用参数，不是线格式；给它们加 tag 反而会暗示
// 存在一份并不存在的对外契约。
type Decision struct {
	// TableName 是产出该判定的表名。
	TableName string `json:"table"`
	// Verdict 是最终判定类别。
	Verdict ActionKind `json:"verdict"`
	// RuleUUID / RuleName 命中的规则；走默认动作时为空。
	RuleUUID string `json:"rule_uuid,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	// Action 是命中的动作（含全部参数）。延迟阻断时它仍然是被延迟的动作本身，
	// 是否已生效由 Deferred 表示。
	Action Action `json:"action"`
	// Allowance 表示本次放行是由白名单（allow 规则）产生的。
	Allowance bool `json:"allowance"`
	// Deferred 表示动作因 defer_after_packets 尚未生效（当前报文只记录不处置）。
	Deferred bool `json:"deferred"`
	// Default 表示未命中任何规则，走的是表级默认动作。
	Default bool `json:"default_action"`
	// Matched 是命中条件的一句话描述列表。
	Matched []string `json:"matched"`
	// Trace 是求值轨迹（含未命中原因），受 TraceLimit 限制。
	Trace []string `json:"trace"`
	// Errors 是求值过程中遇到的数据问题（如属性值类型与字典冲突）。
	// 这类问题不会中断判定，但必须暴露出来 —— 静默忽略会让「规则不生效」无从排查。
	Errors []string `json:"errors"`
}

// EffectiveAction 返回真正需要下发给数据面的动作。
//
// 放行、观察与「延迟未到」三种情况下都不需要执行任何处置：
//   - allow：判定即放行，无动作；
//   - log：只记录；
//   - deferred：动作被推迟到第 N 个报文之后。
func (d Decision) EffectiveAction() (Action, bool) {
	if d.Deferred || d.Verdict == ActionAllow || d.Verdict == ActionLog {
		return Action{}, false
	}
	if len(d.Action.Params.SubActions) == 0 {
		return Action{}, false
	}
	return d.Action, true
}

// String 输出一行式判定摘要，供日志与审计使用。
func (d Decision) String() string {
	who := d.RuleUUID
	switch {
	case d.Allowance:
		who = "白名单:" + who
	case d.Default:
		who = "(默认动作)"
	}
	extra := ""
	if d.Deferred {
		extra = " [延迟未生效]"
	}
	return fmt.Sprintf("表=%s 判定=%s 来源=%s%s", d.TableName, d.Verdict, who, extra)
}

// EngineOptions 控制求值行为。
type EngineOptions struct {
	// TraceLimit 是轨迹条目上限（0 表示使用默认值 64）。
	// 设上限的原因：单条规则的轨迹可能很长，而流量规模下日志量会失控。
	TraceLimit int
}

// defaultTraceLimit 是默认轨迹上限。
const defaultTraceLimit = 64

// Engine 是编译后规则表的判定引擎。
//
// 引擎无状态：同一份属性与上下文，任意次数求值结果一致。这既是可测试性的前提，
// 也让离线影响面预演（用历史 FlowRecord 复算）成为可能。
type Engine struct {
	table      *CompiledTable
	traceLimit int
}

// NewEngine 基于编译产物构造引擎。table 为 nil 时返回一个只做默认动作的引擎，
// 避免调用方到处判空。
func NewEngine(table *CompiledTable, opts EngineOptions) *Engine {
	limit := opts.TraceLimit
	if limit <= 0 {
		limit = defaultTraceLimit
	}
	if table == nil {
		table = &CompiledTable{DefaultAction: Action{Kind: ActionLog}}
	}
	return &Engine{table: table, traceLimit: limit}
}

// Table 返回引擎持有的编译表。
func (e *Engine) Table() *CompiledTable { return e.table }

// Evaluate 对一组属性求值，返回判定结果。
func (e *Engine) Evaluate(attrs Attributes, ctx EvalContext) Decision {
	d := Decision{
		TableName: e.table.Name,
		Trace:     make([]string, 0, 8),
	}

	// 第 1 步：白名单优先。
	for _, r := range e.table.AllowRules {
		matched, trace, errs := r.match(attrs)
		e.appendTrace(&d, trace)
		d.Errors = append(d.Errors, errs...)
		if !matched {
			continue
		}
		d.Verdict = ActionAllow
		d.Allowance = true
		d.RuleUUID = r.source.UUID
		d.RuleName = r.source.Name
		d.Action = r.action
		d.Matched = r.describeMatches(attrs)
		e.appendTrace(&d, []string{"白名单命中，跳过其余规则"})
		return d
	}

	// 第 2 步：其余规则按求值顺序。
	for _, r := range e.table.OtherRules {
		matched, trace, errs := r.match(attrs)
		e.appendTrace(&d, trace)
		d.Errors = append(d.Errors, errs...)
		if !matched {
			continue
		}
		d.Verdict = r.action.Kind
		d.RuleUUID = r.source.UUID
		d.RuleName = r.source.Name
		d.Action = r.action
		d.Matched = r.describeMatches(attrs)
		if r.action.Params.DeferAfterPackets > 0 && ctx.PacketCount < uint64(r.action.Params.DeferAfterPackets) {
			d.Deferred = true
			d.Verdict = ActionLog
			e.appendTrace(&d, []string{fmt.Sprintf(
				"延迟阻断：已处理 %d 个报文，未达阈值 %d，本次仅记录",
				ctx.PacketCount, r.action.Params.DeferAfterPackets)})
		}
		return d
	}

	// 第 3 步：默认动作。
	d.Verdict = e.table.DefaultAction.Kind
	d.Action = e.table.DefaultAction
	d.Default = true
	e.appendTrace(&d, []string{"未命中任何规则，执行表级默认动作"})
	return d
}

func (e *Engine) appendTrace(d *Decision, lines []string) {
	for _, l := range lines {
		if len(d.Trace) >= e.traceLimit {
			return
		}
		d.Trace = append(d.Trace, l)
	}
}

// match 判定规则是否命中，并返回条件级轨迹与数据错误。
//
// 语义：
//   - 条件之间 AND，条件内对象之间 OR（与 TSG 的 and_conditions[].objects[] 一致）；
//   - 条件带 negate 时取反；
//   - 全部条件成立后，再检查排除集：命中任一排除条件则本规则不生效（等价于 NOT(OR(排除))）；
//   - 属性值类型冲突不中断判定，视为该条件不成立，并把原因写入错误列表。
func (r *compiledRule) match(attrs Attributes) (bool, []string, []string) {
	trace := make([]string, 0, len(r.conditions)+1)
	errs := make([]string, 0)

	for _, c := range r.conditions {
		ok, line, err := c.match(attrs)
		if err != nil {
			errs = append(errs, err.Error())
		}
		trace = append(trace, line)
		if !ok {
			return false, trace, errs
		}
	}

	for _, c := range r.excludes {
		ok, line, err := c.match(attrs)
		if err != nil {
			errs = append(errs, err.Error())
		}
		if ok {
			trace = append(trace, "排除集命中，规则不生效: "+line)
			return false, trace, errs
		}
	}
	return true, trace, errs
}

// describeMatches 汇总命中的条件描述，供 Decision.Matched 使用。
func (r *compiledRule) describeMatches(attrs Attributes) []string {
	out := make([]string, 0, len(r.conditions))
	for _, c := range r.conditions {
		ok, line, _ := c.match(attrs)
		if ok {
			out = append(out, line)
		}
	}
	return out
}

// match 判定单个条件。
func (c *compiledCondition) match(attrs Attributes) (bool, string, error) {
	raw := attrs[c.attr.ID]
	if raw == nil {
		// 属性缺失既非「命中」也非「出错」：多数采集场景里属性是按需计算的，
		// 缺失意味着本条件无从判定。此时负条件的语义是「未命中该对象集」，故成立。
		return c.negate, formatConditionLine(c, "属性缺失", nil, c.negate), nil
	}

	var matched bool
	var firstErr error
	hits := make([]string, 0, len(c.objects))
	for _, o := range c.objects {
		ok, err := o.Match(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("条件 %s: %w", c.attr.ID, err)
			}
			continue
		}
		if ok {
			matched = true
			hits = append(hits, o.describe())
		}
	}

	if c.negate {
		matched = !matched
	}
	return matched, formatConditionLine(c, conditionDetail(hits, c.objects, firstErr), firstErr, matched), firstErr
}

// maxExpectDescriptions 是「期望对象集」在轨迹里的展示上限。
//
// 设上限是因为一条规则的对象集可能有上千条 IOC：轨迹被单条规则撑满后，
// 后续规则的判定过程会被挤出 TraceLimit，反而丢失关键信息。
const maxExpectDescriptions = 3

// conditionDetail 生成条件的匹配细节。
//
// 命中时列出「命中了哪些对象」；未命中时改为列出「本来要求匹配什么」——
// 后者才是排查「规则为什么没生效」时真正需要的线索。只输出命中列表会让未命中的
// 条件退化成 `条件 X:  → 不成立` 这样的空信息行，使可解释性恰好在最需要的地方失效。
func conditionDetail(hits []string, objects []*compiledObject, err error) string {
	if len(hits) > 0 {
		return strings.Join(hits, " | ")
	}
	if err != nil {
		// 求值出错与「值不匹配」是两回事，混在一行会让排查方向完全跑偏。
		return "求值出错: " + err.Error()
	}
	expects := make([]string, 0, maxExpectDescriptions+1)
	for i, o := range objects {
		if i == maxExpectDescriptions {
			expects = append(expects, fmt.Sprintf("… 共 %d 个对象", len(objects)))
			break
		}
		expects = append(expects, o.describe())
	}
	return "未匹配任何对象（期望: " + strings.Join(expects, " | ") + "）"
}

// formatConditionLine 统一轨迹行的形状。
//
// 统一形状而非为每种情形写一套模板：轨迹是要被人横向比较的，
// 字段位置一致才能一眼看出「哪一条规则在哪一步停下」。
func formatConditionLine(c *compiledCondition, detail string, err error, matched bool) string {
	attr := c.attr.ID
	if c.negate {
		attr = "¬" + attr
	}
	line := fmt.Sprintf("条件 %s: %s → %s", attr, detail, boolText(matched))
	if c.negate {
		line += "（否定条件）"
	}
	if err != nil && !matched {
		// 未命中且有错误时补一句，避免把数据问题误读为「规则写错了」。
		line += "；该条件因数据问题未参与判定"
	}
	return line
}

// describe 输出单个匹配对象的可读描述。
func (o *compiledObject) describe() string {
	expr := o.object.Expression
	if len(expr) > 64 {
		expr = expr[:64] + "…"
	}
	return fmt.Sprintf("%s(%q, %s, %s)", o.method, expr, o.format, o.def.ID)
}

func boolText(b bool) string {
	if b {
		return "成立"
	}
	return "不成立"
}
