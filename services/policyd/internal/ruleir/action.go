// action.go —— 处置动作模型、参数校验与可用性判定。
//
// 对应 TSG 的 action 与 action_parameter（论文 Table 2、§3.5.1）：
//
//	action: "Deny"
//	action_parameter: { sub_action: "drop", send_tcp_reset: 1,
//	                    after_n_packets: 0, send_icmp_unreachable: 0 }
//
// TSG 把「动作类型」与「执行手段」分开放，这个方向是对的（新增手段不用改规则结构）；
// 但它的手段是散落的布尔开关，组合语义隐含在实现里。本包改为显式的原语数组，
// 并补上 TSG 缺失的三类编译期校验：
//
//  1. **参数校验**：状态码、RST 个数、限速阈值等取值域在编译期检查；
//  2. **协议适配**：向纯 TLS 流注入 HTTP 状态码没有意义 —— 这类错配在编译期报错；
//  3. **部署可用性**：旁路（SPAN/镜像）不在报文路径上，无法丢包也无法限速
//     （论文 §5.2 亦指出 in-path 是丢包的前提）。配置成旁路却使用丢包动作，
//     必须在编译期暴露，而不是等到运行期发现「动作没生效」。
package ruleir

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"cythsec/services/pkg/attributes"
)

// DeployMode 是部署模式。它决定哪些处置原语在物理上可行。
type DeployMode string

const (
	// ModeBypass 旁路：端口镜像 / SPAN / TAP。只能观测与注入，不能丢弃或限速。
	ModeBypass DeployMode = "bypass"
	// ModeOnPathInline 在线内联：报文经过本机转发生效，全部原语可用。
	ModeOnPathInline DeployMode = "on_path_inline"
	// ModeOnPathTransparent 在线透明：不重写 MAC 的不完整 L2 转发，原语可用性同内联。
	ModeOnPathTransparent DeployMode = "on_path_transparent"
	// ModePcap 离线回放：用于测试床与影响面评估，原语以「写入输出 pcap」方式模拟。
	ModePcap DeployMode = "pcap"
)

// AllDeployModes 返回全部部署模式（按可用性由弱到强排列）。
func AllDeployModes() []DeployMode {
	return []DeployMode{ModeBypass, ModePcap, ModeOnPathTransparent, ModeOnPathInline}
}

// Valid 判断部署模式是否为已登记取值。
func (m DeployMode) Valid() bool {
	for _, x := range AllDeployModes() {
		if x == m {
			return true
		}
	}
	return false
}

// InPath 表示该模式是否位于报文转发路径上（决定能否丢包/限速）。
func (m DeployMode) InPath() bool {
	return m == ModeOnPathInline || m == ModeOnPathTransparent
}

// SubActionAvailable 判断某处置原语在给定部署模式下是否可用。
//
// 这是把「部署模式」从文档约定提升为代码约束的关键函数：调用方（控制台、下发前的
// 预检、求值引擎）都必须经它判断，不允许各自硬编码一遍。
func SubActionAvailable(sub SubAction, mode DeployMode) bool {
	if !sub.Valid() {
		return false
	}
	if mode.InPath() || mode == ModePcap {
		return true
	}
	if mode == ModeBypass {
		switch sub {
		case SubDropStream, SubDropCurrentPacket, SubThrottleSession, SubThrottlePacket:
			// 旁路不在报文路径上：丢包与限速无从谈起；注入类原语仍然可行。
			return false
		}
		return true
	}
	return false
}

// requiredProtocol 返回处置原语要求的协议上下文；空串表示与协议无关。
func requiredProtocol(sub SubAction) string {
	switch sub {
	case SubResetStream:
		return "tcp"
	case SubInjectHTTPStatus, SubInjectHTTPRedirect:
		return "http"
	case SubInjectDNSRedirect:
		return "dns"
	case SubInjectSMTPReply:
		return "smtp"
	case SubInjectSIPReply:
		return "sip"
	}
	return ""
}

// RequiredProtocol 是 requiredProtocol 的导出形式，供控制台与规则编辑器展示
// 「该原语需要什么协议上下文」。
func RequiredProtocol(sub SubAction) string { return requiredProtocol(sub) }

// protocolOfAttribute 由属性标识推断协议上下文；空串表示通用属性。
//
// 用前缀推断而非让用户逐个声明，是因为属性的命名已经编码了协议语义；
// 但推断只能收窄不能创造 —— 推断不出且动作要求协议时，编译期要求显式声明
// rule.protocol（见 validateProtocol）。
func protocolOfAttribute(attr string) string {
	switch {
	case strings.HasPrefix(attr, "ATTR_HTTP_"):
		return "http"
	case strings.HasPrefix(attr, "ATTR_DNS_"):
		return "dns"
	case strings.HasPrefix(attr, "ATTR_TLS_"):
		return "tls"
	case strings.HasPrefix(attr, "ATTR_QUIC_"):
		return "quic"
	case strings.HasPrefix(attr, "ATTR_SSH_"):
		return "ssh"
	case strings.HasPrefix(attr, "ATTR_SMTP_"):
		return "smtp"
	case strings.HasPrefix(attr, "ATTR_SIP_"):
		return "sip"
	case strings.HasPrefix(attr, "ATTR_TCP_"):
		return "tcp"
	case attr == attributes.UDPLen:
		return "udp"
	}
	return ""
}

// inferProtocols 由规则的条件与排除集推断协议集合。
//
// 只返回明确的协议；通用属性（五元组、流统计、载荷窗口等）不参与推断，
// 因为它们可以出现在任何协议的流上。
func inferProtocols(r Rule) map[string]bool {
	out := map[string]bool{}
	add := func(cs []Condition) {
		for _, c := range cs {
			if p := protocolOfAttribute(c.Attribute); p != "" {
				out[p] = true
			}
		}
	}
	add(r.Conditions)
	add(r.Excludes)
	return out
}

// validateProtocol 校验动作所需的协议上下文是否成立。
func validateProtocol(r Rule, a Action) []Diagnostic {
	out := make([]Diagnostic, 0)
	inferred := inferProtocols(r)
	for _, sub := range a.Params.SubActions {
		need := requiredProtocol(sub)
		if need == "" {
			continue
		}
		switch {
		case r.Protocol != "":
			if !protocolSatisfies(r.Protocol, need) {
				out = append(out, Diagnostic{
					Severity: SeverityError, Code: "action.protocol_mismatch", RuleUUID: r.UUID,
					Message: fmt.Sprintf("原语 %s 需要协议 %s，但规则声明 protocol=%s",
						sub, need, r.Protocol),
				})
			}
		case len(inferred) == 0:
			out = append(out, Diagnostic{
				Severity: SeverityError, Code: "action.protocol_missing", RuleUUID: r.UUID,
				Message: fmt.Sprintf("原语 %s 需要协议 %s，但规则条件未引用任何协议属性，"+
					"且未声明 protocol", sub, need),
			})
		case !inferred[need]:
			out = append(out, Diagnostic{
				Severity: SeverityError, Code: "action.protocol_mismatch", RuleUUID: r.UUID,
				Message: fmt.Sprintf("原语 %s 需要协议 %s，但条件推断出的协议为 %s",
					sub, need, joinProtocols(inferred)),
			})
		}
	}
	return out
}

// protocolSatisfies 判断声明的协议是否能承载所需协议。
//
// 目前只处理一条包含关系：http 运行在 TLS 之上，故 protocol=tls 不能承载 HTTP 注入，
// 而 protocol=http 可以承载需要 http 的原语。tls 与 quic 是并列的，不互相满足。
func protocolSatisfies(declared, need string) bool {
	if declared == need {
		return true
	}
	return false
}

func joinProtocols(m map[string]bool) string {
	parts := make([]string, 0, len(m))
	for k := range m {
		parts = append(parts, k)
	}
	// 稳定输出，便于测试比对。
	for i := 0; i < len(parts); i++ {
		for j := i + 1; j < len(parts); j++ {
			if parts[j] < parts[i] {
				parts[i], parts[j] = parts[j], parts[i]
			}
		}
	}
	return strings.Join(parts, "/")
}

// allowedICMPCodes 是允许的 ICMP 不可达 code 集合（RFC 792 / RFC 1122 常用子集）。
var allowedICMPCodes = map[int]bool{0: true, 1: true, 2: true, 3: true, 9: true, 10: true, 13: true}

// allowedHTTPStatus 是允许注入的 HTTP 状态码，取值集合对齐 TSG（论文 §3.5.1）。
var allowedHTTPStatus = map[int]bool{200: true, 204: true, 403: true, 404: true}

// allowedHTTPRedirect 是允许的重定向状态码。
var allowedHTTPRedirect = map[int]bool{302: true, 303: true}

// allowedSMTPCodes 是允许注入的 SMTP 应答码，对齐 TSG 的两条固定应答。
var allowedSMTPCodes = map[int]bool{550: true, 551: true}

// allowedSIPCodes 是允许注入的 SIP 应答码。
var allowedSIPCodes = map[int]bool{480: true, 500: true}

// normalizeAction 补默认值并对齐内部约定，返回归一化后的动作与诊断。
//
// 归一化让求值阶段不必再处理「未指定手段的 deny」这类中间态：编译后的表是确定契约。
func normalizeAction(r Rule, mode DeployMode) (Action, []Diagnostic) {
	diags := make([]Diagnostic, 0)
	a := cloneAction(r.Action)

	if !a.Kind.Valid() {
		diags = append(diags, Diagnostic{
			Severity: SeverityError, Code: "action.unknown_kind", RuleUUID: r.UUID,
			Message: fmt.Sprintf("动作大类 %q 未登记（可用：allow/deny/log/throttle/redirect）", a.Kind),
		})
		return a, diags
	}

	// 大类与手段的一致性。
	switch a.Kind {
	case ActionAllow:
		if len(a.Params.SubActions) > 0 {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "action.allow_has_subaction", RuleUUID: r.UUID,
				Message: "allow 规则是白名单，不应携带处置原语",
			})
		}
	case ActionLog:
		if len(a.Params.SubActions) > 0 {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "action.log_has_subaction", RuleUUID: r.UUID,
				Message: "log 规则只记录不处置，不应携带处置原语（如需同时限速请使用 throttle）",
			})
		}
	case ActionDeny:
		if len(a.Params.SubActions) == 0 {
			// TSG 的 deny 隐含「丢弃」；这里显式化，避免「拒了但没动作」的空转。
			a.Params.SubActions = []SubAction{SubDropStream}
			diags = append(diags, Diagnostic{
				Severity: SeverityWarning, Code: "action.deny_defaulted", RuleUUID: r.UUID,
				Message: "deny 未指定处置原语，已按 drop_stream 归一化",
			})
		}
	case ActionThrottle:
		if !hasAnySubAction(a.Params.SubActions, SubThrottleSession, SubThrottlePacket) {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "action.throttle_without_primitive", RuleUUID: r.UUID,
				Message: "throttle 动作必须包含 throttle_session 或 throttle_packet",
			})
		}
	case ActionRedirect:
		if !hasAnySubAction(a.Params.SubActions, SubInjectHTTPRedirect, SubInjectDNSRedirect) {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "action.redirect_without_primitive", RuleUUID: r.UUID,
				Message: "redirect 动作必须包含 inject_http_redirect 或 inject_dns_redirect",
			})
		}
	}

	// 逐原语校验：登记状态、部署可用性、参数取值域。
	seen := map[SubAction]bool{}
	for _, sub := range a.Params.SubActions {
		if !sub.Valid() {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "action.unknown_subaction", RuleUUID: r.UUID,
				Message: fmt.Sprintf("处置原语 %q 未登记（可用：%s）", sub, joinSubActions(SubActions())),
			})
			continue
		}
		if seen[sub] {
			diags = append(diags, Diagnostic{
				Severity: SeverityWarning, Code: "action.duplicate_subaction", RuleUUID: r.UUID,
				Message: fmt.Sprintf("处置原语 %s 重复出现，已去重", sub),
			})
			continue
		}
		seen[sub] = true
		if !SubActionAvailable(sub, mode) {
			diags = append(diags, Diagnostic{
				Severity: SeverityError, Code: "action.mode_unavailable", RuleUUID: r.UUID,
				Message: fmt.Sprintf("处置原语 %s 在部署模式 %s 下不可用"+
					"（旁路只能观测与注入，无法丢包/限速）", sub, mode),
			})
		}
		diags = append(diags, validateParams(r.UUID, sub, a.Params)...)
	}

	// 去重（保留首次出现顺序）。
	if len(a.Params.SubActions) > 1 {
		uniq := make([]SubAction, 0, len(a.Params.SubActions))
		seen = map[SubAction]bool{}
		for _, sub := range a.Params.SubActions {
			if seen[sub] {
				continue
			}
			seen[sub] = true
			uniq = append(uniq, sub)
		}
		a.Params.SubActions = uniq
	}

	diags = append(diags, validateDefer(r, a)...)
	diags = append(diags, validateProtocol(r, a)...)
	return a, diags
}

// validateParams 校验原语自身的参数取值域。
func validateParams(uuid string, sub SubAction, p ActionParams) []Diagnostic {
	out := make([]Diagnostic, 0)
	add := func(msg string) {
		out = append(out, Diagnostic{
			Severity: SeverityError, Code: "action.param_invalid", RuleUUID: uuid,
			Message: fmt.Sprintf("原语 %s 参数非法: %s", sub, msg),
		})
	}

	switch sub {
	case SubResetStream:
		if p.ResetCount != 0 && (p.ResetCount < 1 || p.ResetCount > 3) {
			add(fmt.Sprintf("reset_count=%d 越界（允许 1..3，对齐 TSG 的可配范围）", p.ResetCount))
		}
		if p.ResetFlags != "" && p.ResetFlags != "rst" && p.ResetFlags != "rst_ack" {
			add(fmt.Sprintf("reset_flags=%q 未登记（允许 rst / rst_ack）", p.ResetFlags))
		}
	case SubInjectICMPUnreachable:
		if !allowedICMPCodes[p.ICMPCode] {
			add(fmt.Sprintf("icmp_code=%d 不在允许集合 {0,1,2,3,9,10,13}", p.ICMPCode))
		}
	case SubInjectHTTPStatus:
		if !allowedHTTPStatus[p.HTTPStatusCode] {
			add(fmt.Sprintf("http_status_code=%d 不在允许集合 {200,204,403,404}", p.HTTPStatusCode))
		}
	case SubInjectHTTPRedirect:
		if !allowedHTTPRedirect[p.RedirectCode] {
			add(fmt.Sprintf("redirect_code=%d 不在允许集合 {302,303}", p.RedirectCode))
		}
		if strings.TrimSpace(p.RedirectURL) == "" {
			add("redirect_url 为空")
		} else if u, err := url.Parse(p.RedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
			add(fmt.Sprintf("redirect_url=%q 不是绝对 URL（需含 scheme 与 host）", p.RedirectURL))
		}
	case SubInjectDNSRedirect:
		if len(p.DNSAnswers) == 0 {
			add("dns_answers 为空")
		}
		for _, ans := range p.DNSAnswers {
			if net.ParseIP(strings.TrimSpace(ans)) == nil {
				add(fmt.Sprintf("dns_answers 中的 %q 不是合法 IP", ans))
			}
		}
	case SubInjectSMTPReply:
		if !allowedSMTPCodes[p.SMTPCode] {
			add(fmt.Sprintf("smtp_code=%d 不在允许集合 {550,551}", p.SMTPCode))
		}
	case SubInjectSIPReply:
		if !allowedSIPCodes[p.SIPCode] {
			add(fmt.Sprintf("sip_code=%d 不在允许集合 {480,500}", p.SIPCode))
		}
	case SubThrottleSession, SubThrottlePacket:
		if p.ThrottleBps <= 0 {
			add(fmt.Sprintf("throttle_bps=%d 必须为正数", p.ThrottleBps))
		}
	}
	return out
}

// validateDefer 校验延迟阻断与其他原语的组合语义。
func validateDefer(r Rule, a Action) []Diagnostic {
	out := make([]Diagnostic, 0)
	if a.Params.DeferAfterPackets < 0 {
		out = append(out, Diagnostic{
			Severity: SeverityError, Code: "action.param_invalid", RuleUUID: r.UUID,
			Message: fmt.Sprintf("defer_after_packets=%d 不能为负", a.Params.DeferAfterPackets),
		})
		return out
	}
	if a.Params.DeferAfterPackets == 0 {
		return out
	}
	for _, sub := range a.Params.SubActions {
		switch sub {
		case SubDropStream, SubDropCurrentPacket:
			// 丢乱流是「立即生效」语义：延迟到第 N 个包再丢流，等价于「前 N 个包照常
			// 转发、之后整条流丢弃」，与 drop_stream 的直觉不符，多半是配置错误。
			out = append(out, Diagnostic{
				Severity: SeverityWarning, Code: "action.combination_useless", RuleUUID: r.UUID,
				Message: fmt.Sprintf("defer_after_packets=%d 与 %s 组合语义可疑："+
					"延迟期间报文会正常转发，请确认这是预期行为",
					a.Params.DeferAfterPackets, sub),
			})
		}
	}
	return out
}

func hasAnySubAction(list []SubAction, want ...SubAction) bool {
	for _, got := range list {
		for _, w := range want {
			if got == w {
				return true
			}
		}
	}
	return false
}

func joinSubActions(subs []SubAction) string {
	parts := make([]string, 0, len(subs))
	for _, s := range subs {
		parts = append(parts, string(s))
	}
	return strings.Join(parts, "/")
}
