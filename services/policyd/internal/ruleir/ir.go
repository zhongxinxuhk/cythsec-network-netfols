// Package ruleir 实现 policyd 的策略规则中间表示（IR）与判定引擎。
//
// 设计来源：TSG（Tiangou Secure Gateway，天狗安全网关）泄漏源码的技术分析
// （Ablove et al., 35th USENIX Security Symposium, 2026）中描述的 Maat 规则引擎。
// 论文可确认的三条设计被直接采纳：
//
//  1. **匹配语义与格式归一化正交**：match_method 决定「怎么比」（全等/前缀/包含/正则/
//     网段/区间/集合），format 决定「比之前怎么归一」（原样/忽略大小写/十六进制/base64）。
//     两者是独立维度，写进同一个字段会让新增匹配方式排列组合式膨胀。
//  2. **负条件是一等公民**：条件自带 negate；「排除集」也是显式字段（Rule.Excludes），
//     而不是靠「黑名单里不写它」来规避 —— 后者无法表达「命中 A 且不命中 B」。
//  3. **动作类型与动作参数解耦**：动作由 Kind + Params 组成，Params 携带 sub_actions 与
//     after_n_packets 之类参数。新增动作不需要改动规则结构。
//
// 论文同时暴露了 TSG 的两处工程缺陷，本包针对性补上：
//
//   - Maat 规则表没有冲突/冗余/自相矛盾检测，误配只能靠运行期表现暴露
//     → 本包在编译期产出诊断（见 compile.go）；
//   - 误封依赖人工流程事后补救，且白名单是误封之后才补上的机制
//     → 本包把「白名单先于拒绝」固化进求值顺序（见 evaluate.go）。
//
// 明确不属于本包的范围：**报文的实际构造与注入**。本包只产出「应当执行什么动作」的
// 结构化决策；执行由数据面承担，依赖 CYS-PKT-024（C++ ↔ Rust 共享内存契约）落地。
package ruleir

import (
	"fmt"
	"sort"
	"strings"
)

// Attributes 是一次判定输入：属性规范标识（ATTR_*）-> 值。
//
// 值的承载类型按属性字典的 ValueType 约定：
//
//	string / enum / ip / time_ms -> string
//	bytes                        -> []byte（亦接受十六进制字符串，见 normalize）
//	port / u8 / u16 / u32 / u64  -> uint64（JSON 解码后的 float64 会被归一）
//	i64                          -> int64
//	bool                         -> bool
//	string_set                   -> []string
//
// 之所以在这里做「宽容入参 + 归一化」，是因为属性值的来源有三个：数据面共享内存
// （原生整型）、控制面 JSON（数字一律 float64）、离线回放（字符串）。要求每个调用方
// 自己转成规范类型，等于把同一段转换逻辑复制三份。
type Attributes map[string]any

// Clone 返回属性集合的浅拷贝，避免调用方在判定过程中被并发修改。
func (a Attributes) Clone() Attributes {
	out := make(Attributes, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}

// Keys 按字典序返回全部属性标识，便于日志与测试的稳定输出。
func (a Attributes) Keys() []string {
	out := make([]string, 0, len(a))
	for k := range a {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ActionKind 是动作大类。分类依据是「判定结果的性质」，而非具体执行手段：
// 具体执行手段由 ActionParams.SubActions 描述。
type ActionKind string

const (
	// ActionAllow 显式放行。语义特殊：allow 规则构成白名单，在求值顺序上**先于**拒绝判定。
	ActionAllow ActionKind = "allow"
	// ActionDeny 拒绝（具体手段见 SubActions；未指定手段时等价于丢弃当前流）。
	ActionDeny ActionKind = "deny"
	// ActionLog 只记录不阻断，用于观察期与影响面评估。
	ActionLog ActionKind = "log"
	// ActionThrottle 限速（会话级或包级）。
	ActionThrottle ActionKind = "throttle"
	// ActionRedirect 重定向（HTTP / DNS 两类，手段由 SubActions 指定）。
	ActionRedirect ActionKind = "redirect"
)

// Valid 判断动作大类是否为已登记取值。
func (k ActionKind) Valid() bool {
	switch k {
	case ActionAllow, ActionDeny, ActionLog, ActionThrottle, ActionRedirect:
		return true
	}
	return false
}

// AllActionKinds 返回全部动作大类（固定顺序，供控制台与校验使用）。
func AllActionKinds() []ActionKind {
	return []ActionKind{ActionAllow, ActionDeny, ActionThrottle, ActionRedirect, ActionLog}
}

// SubAction 是数据面可执行的处置原语。
//
// 命名与 TSG 的 stream.h / action_parameter 语义对齐（论文 §3.1、§3.5.1），
// 但做了两处收敛：
//   - TSG 把「发 1–3 个 RST」「RST 还是 RST+ACK」拆成配置项，这里合并进
//     ActionParams.ResetCount / ResetFlags，保持原语与参数分离；
//   - TSG 的载荷篡改原语（交换载荷首尾各 2 字节后重放）**未纳入实现**：它只有
//     「破坏对端会话」这一种效果，没有对应的检测价值，而执行层的其余原语
//     都有各自的可观测用途（丢包=隔离、RST=断连、重定向=引流到诱捕、限速=压制）。
type SubAction string

const (
	// SubDropStream 丢弃该流后续全部报文；需 on-path 部署（旁路无法丢包）。
	SubDropStream SubAction = "drop_stream"
	// SubDropCurrentPacket 仅丢弃当前报文，保留流状态。
	SubDropCurrentPacket SubAction = "drop_current_packet"
	// SubResetStream 构造并发送 TCP RST。参数：ResetCount（1..3）、ResetFlags（rst / rst_ack）。
	// TSG 默认发 1 个 RST+ACK；本项目默认 1 个 rst_ack 以对齐主流实现，但由配置决定。
	SubResetStream SubAction = "reset_stream"
	// SubInjectICMPUnreachable 注入 ICMP 不可达。参数：ICMPCode。
	SubInjectICMPUnreachable SubAction = "inject_icmp_unreachable"
	// SubThrottleSession 会话级限速：以 ThrottleBps 为桶容量丢弃报文。
	SubThrottleSession SubAction = "throttle_session"
	// SubThrottlePacket 包级限速：丢弃尺寸超过 ThrottleBps 的报文。
	SubThrottlePacket SubAction = "throttle_packet"
	// SubInjectHTTPStatus 注入 HTTP 状态码响应。参数：HTTPStatusCode（200/204/403/404）。
	SubInjectHTTPStatus SubAction = "inject_http_status"
	// SubInjectHTTPRedirect 注入 HTTP 重定向。参数：RedirectCode（302/303）、RedirectURL。
	SubInjectHTTPRedirect SubAction = "inject_http_redirect"
	// SubInjectDNSRedirect 注入 DNS 应答。参数：DNSAnswers（应答地址列表）。
	SubInjectDNSRedirect SubAction = "inject_dns_redirect"
	// SubInjectSMTPReply 注入 SMTP 应答。参数：SMTPCode（550/551）、SMTPText。
	SubInjectSMTPReply SubAction = "inject_smtp_reply"
	// SubInjectSIPReply 注入 SIP 应答。参数：SIPCode（480/500）、SIPText。
	SubInjectSIPReply SubAction = "inject_sip_reply"
)

// SubActions 返回全部已登记的处置原语，供控制台与校验使用。
func SubActions() []SubAction {
	return []SubAction{
		SubDropStream, SubDropCurrentPacket, SubResetStream, SubInjectICMPUnreachable,
		SubThrottleSession, SubThrottlePacket,
		SubInjectHTTPStatus, SubInjectHTTPRedirect, SubInjectDNSRedirect,
		SubInjectSMTPReply, SubInjectSIPReply,
	}
}

// Valid 判断处置原语是否为已登记取值。
func (s SubAction) Valid() bool {
	for _, x := range SubActions() {
		if x == s {
			return true
		}
	}
	return false
}

// ActionParams 是动作参数。零值即「无参数」，对不需要参数的原语是合法状态。
//
// 与 TSG 的 action_parameter 对应关系：
//
//	send_tcp_reset        -> SubResetStream + ResetCount/ResetFlags
//	send_icmp_unreachable -> SubInjectICMPUnreachable + ICMPCode
//	after_n_packets       -> DeferAfterPackets
//	（TSG 的 sub_action 是隐式字符串，这里改为显式数组，允许一条规则组合多个原语）
type ActionParams struct {
	// SubActions 是本规则命中的处置原语集合；为空表示「仅判定不处置」（观察态）。
	SubActions []SubAction `json:"sub_actions,omitempty"`
	// DeferAfterPackets > 0 时，前 N 个报文只记录不处置（TSG 的延迟阻断）。
	// 用途是给误封留出观察窗口，而非降低时延。
	DeferAfterPackets int `json:"defer_after_packets,omitempty"`
	// ThrottleBps 限速阈值（字节/秒），配合 SubThrottle* 使用。
	ThrottleBps int64 `json:"throttle_bps,omitempty"`
	// ResetCount 是每个阻断决策发出的 RST 个数，TSG 可配 1–3。
	ResetCount int `json:"reset_count,omitempty"`
	// ResetFlags 取 rst 或 rst_ack；TSG 对应 FLAGS=4 / FLAGS=20。
	ResetFlags string `json:"reset_flags,omitempty"`
	// ICMPCode 是 ICMP 不可达的 code 字段。
	ICMPCode int `json:"icmp_code,omitempty"`
	// HTTPStatusCode 是注入响应的状态码。
	HTTPStatusCode int `json:"http_status_code,omitempty"`
	// RedirectCode 是重定向状态码（302/303），RedirectURL 是目标地址。
	RedirectCode int    `json:"redirect_code,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	// DNSAnswers 是 DNS 重定向要返回的地址列表。
	DNSAnswers []string `json:"dns_answers,omitempty"`
	// SMTPCode / SMTPText 与 SIPCode / SIPText 是协议应答的码值与文本。
	SMTPCode int    `json:"smtp_code,omitempty"`
	SMTPText string `json:"smtp_text,omitempty"`
	SIPCode  int    `json:"sip_code,omitempty"`
	SIPText  string `json:"sip_text,omitempty"`
}

// Action 是规则命中后要执行的判定结果。
type Action struct {
	Kind   ActionKind   `json:"kind"`
	Params ActionParams `json:"params,omitempty"`
}

// MatchObject 是单个匹配对象：表达式 + 匹配语义 + 格式归一化。
//
// 三者正交（论文 §3.4 的 Maat 设计）：同一表达式换匹配语义即可从「全等域名」变成
// 「域名后缀」，换格式即可从「区分大小写」变成「忽略大小写」，无需新增字段。
type MatchObject struct {
	// Expression 是匹配表达式，其合法形式由属性的 ValueType 与 Method 共同决定。
	Expression string `json:"expression"`
	// MatchMethod 见 match.go 的语义表；留空时按属性类型取默认方法。
	MatchMethod MatchMethod `json:"match_method,omitempty"`
	// Format 见 match.go；留空时按属性类型取默认格式（文本 uncase，字节 hex）。
	Format Format `json:"format,omitempty"`
}

// Condition 是单个条件：同一条件内的多个对象之间是 **OR**，条件之间是 **AND**。
//
// 这一组合语义直接对齐 TSG 的 and_conditions[].objects[]（论文 Table 2）：
// AND 负责「多维度同时成立」，OR 负责「同一维度多值」，二者缺一都会逼出重复规则。
type Condition struct {
	// Attribute 是属性规范标识（ATTR_*）。
	Attribute string `json:"attribute"`
	// Negate 为真时对该条件取反 —— 负条件是一等公民。
	Negate bool `json:"negate,omitempty"`
	// Objects 是匹配对象列表，命中任一即该条件成立。
	Objects []MatchObject `json:"objects"`
}

// Rule 是一条规则。
type Rule struct {
	// UUID 是规则稳定标识，用于审计与诊断定位。
	UUID string `json:"uuid"`
	// Name 是人类可读名称。
	Name string `json:"name,omitempty"`
	// Enabled 为 false 时规则参与编译但不参与求值。
	Enabled bool `json:"enabled"`
	// EvaluationOrder 是求值顺序，数值小的先求值（对齐 TSG 的 evaluation_order）。
	// 与 Priority 分开：顺序决定「谁先被问」，优先级决定「谁更权威」，混用会让
	// 排序语义随实现漂移。
	EvaluationOrder float64 `json:"evaluation_order"`
	// Conditions 之间取 AND；为空表示无条件命中（仅用于表级默认动作或观察规则）。
	Conditions []Condition `json:"conditions,omitempty"`
	// Excludes 是排除集：命中任一排除条件则本规则不生效。
	// 对应 TSG 为抑制误封而引入的「Ip 段 + 白名单保护」形态（论文 §4.1.2）。
	Excludes []Condition `json:"excludes,omitempty"`
	// Action 是命中后的判定结果。
	Action Action `json:"action"`
	// Protocol 是规则适用的协议上下文（http / dns / tls / quic / smtp / sip / tcp / udp）。
	// 留空时由条件引用的属性前缀推断；推断不出且动作要求特定协议时，编译期报错。
	Protocol string `json:"protocol,omitempty"`
	// Description 是规则意图说明，进审计日志。
	Description string `json:"description,omitempty"`
}

// Table 是一张规则表。表的划分用于隔离不同判定面（安全策略 / 白名单 / 观察态），
// 而不是按业务分类 —— 表的边界决定了求值顺序的边界。
type Table struct {
	Name string `json:"name"`
	// Service 是服务标识（对齐 TSG 的 service 字段），用于多判定面共存时区分调用方。
	Service uint16 `json:"service,omitempty"`
	// DefaultAction 是未命中任何规则时的动作。零值时由编译期补为「放行 + 记录」。
	DefaultAction Action `json:"default_action,omitempty"`
	Rules         []Rule `json:"rules"`
}

// Clone 深拷贝规则表，避免编译产物被调用方修改（编译后的表是只读契约）。
func (t *Table) Clone() *Table {
	if t == nil {
		return nil
	}
	out := &Table{Name: t.Name, Service: t.Service, DefaultAction: cloneAction(t.DefaultAction)}
	out.Rules = make([]Rule, len(t.Rules))
	for i, r := range t.Rules {
		out.Rules[i] = cloneRule(r)
	}
	return out
}

func cloneRule(r Rule) Rule {
	out := r
	if r.Conditions != nil {
		out.Conditions = cloneConditions(r.Conditions)
	}
	if r.Excludes != nil {
		out.Excludes = cloneConditions(r.Excludes)
	}
	out.Action = cloneAction(r.Action)
	return out
}

func cloneConditions(in []Condition) []Condition {
	out := make([]Condition, len(in))
	for i, c := range in {
		out[i] = c
		out[i].Objects = make([]MatchObject, len(c.Objects))
		copy(out[i].Objects, c.Objects)
	}
	return out
}

func cloneAction(a Action) Action {
	out := a
	if a.Params.SubActions != nil {
		out.Params.SubActions = make([]SubAction, len(a.Params.SubActions))
		copy(out.Params.SubActions, a.Params.SubActions)
	}
	if a.Params.DNSAnswers != nil {
		out.Params.DNSAnswers = make([]string, len(a.Params.DNSAnswers))
		copy(out.Params.DNSAnswers, a.Params.DNSAnswers)
	}
	return out
}

// AttributeNames 返回本表全部条件与排除集引用到的属性标识（去重、字典序）。
//
// 用途：调用方据此只计算「本表真正需要」的属性，从而把属性字典的 stage/cost
// 分级落到实处 —— 一份只引用 packet 阶段属性的表，不该触发 l7 解析。
func (t *Table) AttributeNames() []string {
	set := map[string]struct{}{}
	for _, r := range t.Rules {
		for _, c := range r.Conditions {
			set[c.Attribute] = struct{}{}
		}
		for _, c := range r.Excludes {
			set[c.Attribute] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// String 输出规则的可读摘要，用于诊断信息与日志（不含属性值，避免敏感数据入日志）。
func (r Rule) String() string {
	name := r.Name
	if name == "" {
		name = r.UUID
	}
	return fmt.Sprintf("规则[%s] 顺序=%.2f 条件=%d 排除=%d 动作=%s%s",
		name, r.EvaluationOrder, len(r.Conditions), len(r.Excludes),
		r.Action.Kind, subActionSuffix(r.Action.Params.SubActions))
}

func subActionSuffix(subs []SubAction) string {
	if len(subs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(subs))
	for _, s := range subs {
		parts = append(parts, string(s))
	}
	return "(" + strings.Join(parts, ",") + ")"
}
