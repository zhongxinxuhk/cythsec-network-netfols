// match.go —— 匹配语义（match_method）与格式归一化（format）两个正交维度。
//
// 移植自 TSG/Maat 的核心设计。论文 Table 2 给出的 Maat 条件是：
//
//	objects[0] = { expression: "blocked.com", match_method: "full", format: "uncase plain" }
//
// 这三个字段的关系是「值 + 怎么比 + 比之前怎么归一」。把它们拆开的价值在于：新增一种
// 匹配方式不需要动格式逻辑，反之亦然；而把三者揉成一个字段（如 "iocontains"）会让
// 「忽略大小写的包含」与「区分大小写的包含」变成两条规则语法。
//
// 本文件同时是「属性类型 → 可用匹配方法」的唯一裁定处。不合法组合（例如对整数属性用
// regex、对多值表达式用 full）在编译期报错，而不是在运行期静默不匹配 —— 后者是规则
// 引擎最难排查的故障模式：规则看起来加载成功，却永远不生效。
package ruleir

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"cythsec/services/pkg/attributes"
)

// MatchMethod 是匹配语义。
type MatchMethod string

const (
	// MethodFull 全等。
	MethodFull MatchMethod = "full"
	// MethodPrefix 前缀。
	MethodPrefix MatchMethod = "prefix"
	// MethodSuffix 后缀（域名场景最常用，如 .com / .gov.au）。
	MethodSuffix MatchMethod = "suffix"
	// MethodContains 包含。
	MethodContains MatchMethod = "contains"
	// MethodRegex 正则（表达式为 RE2 语法）。
	MethodRegex MatchMethod = "regex"
	// MethodCIDR 网段归属：值落在表达式指定的网段内（IP）或为其子网（网段）。
	MethodCIDR MatchMethod = "cidr"
	// MethodRange 数值区间，表达式形如 "1024..65535"、">=1024"、"1024.."。
	MethodRange MatchMethod = "range"
	// MethodSet 集合匹配：表达式为多值集合，值与集合的交集非空即命中。
	MethodSet MatchMethod = "set"
)

// AllMatchMethods 返回全部匹配方法（字典序），供控制台下拉与文档生成使用。
func AllMatchMethods() []MatchMethod {
	out := []MatchMethod{
		MethodFull, MethodPrefix, MethodSuffix, MethodContains,
		MethodRegex, MethodCIDR, MethodRange, MethodSet,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Valid 判断匹配方法是否为已登记取值。
func (m MatchMethod) Valid() bool {
	for _, x := range AllMatchMethods() {
		if x == m {
			return true
		}
	}
	return false
}

// Format 是匹配前的格式归一化。
type Format string

const (
	// FormatPlain 原样比较。
	FormatPlain Format = "plain"
	// FormatUncase 忽略大小写（两侧统一为小写后比较）。
	FormatUncase Format = "uncase"
	// FormatLower 显式小写。归一化结果与 uncase 一致，但表达的是「值本应已是小写」的
	// 断言意图；保留区分是为了让规则作者能表达「这是域名」而非「顺便忽略大小写」。
	FormatLower Format = "lower"
	// FormatHex 十六进制：表达式与值都按十六进制解码为字节后比较。
	FormatHex Format = "hex"
	// FormatBase64 Base64：表达式按 Base64 解码为字节后比较。
	FormatBase64 Format = "base64"
)

// AllFormats 返回全部格式取值（字典序）。
func AllFormats() []Format {
	out := []Format{FormatPlain, FormatUncase, FormatLower, FormatHex, FormatBase64}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Valid 判断格式是否为已登记取值。
func (f Format) Valid() bool {
	for _, x := range AllFormats() {
		if x == f {
			return true
		}
	}
	return false
}

// methodSpec 描述某个 ValueType 支持的匹配方法与默认取值。
type methodSpec struct {
	methods       []MatchMethod
	defaultMethod MatchMethod
	defaultFormat Format
}

// methodTable 是「属性类型 → 可用匹配方法」的唯一裁定表。
//
// 设计原则：宁可少支持也不给模糊语义。例如允许对整数用 prefix 会引出「数值 12 是否
// 前缀匹配 123」这类无共识问题，因此数值类型只给 full/range/set。
var methodTable = map[attributes.ValueType]methodSpec{
	attributes.ValueTypeString: {[]MatchMethod{
		MethodFull, MethodPrefix, MethodSuffix, MethodContains, MethodRegex, MethodSet,
	}, MethodFull, FormatUncase},
	attributes.ValueTypeEnum: {[]MatchMethod{
		MethodFull, MethodSet,
	}, MethodFull, FormatUncase},
	attributes.ValueTypeBytes: {[]MatchMethod{
		MethodFull, MethodPrefix, MethodSuffix, MethodContains, MethodSet,
	}, MethodPrefix, FormatHex},
	attributes.ValueTypeIP: {[]MatchMethod{
		MethodFull, MethodCIDR, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeIPPrefix: {[]MatchMethod{
		MethodFull, MethodCIDR, MethodSet,
	}, MethodCIDR, FormatPlain},
	attributes.ValueTypePort: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeU8: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeU16: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeU32: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeU64: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeI64: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeTimeMs: {[]MatchMethod{
		MethodFull, MethodRange, MethodSet,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeBool: {[]MatchMethod{
		MethodFull,
	}, MethodFull, FormatPlain},
	attributes.ValueTypeStringSet: {[]MatchMethod{
		MethodFull, MethodSet, MethodContains,
	}, MethodSet, FormatUncase},
}

// MethodsFor 返回指定值类型支持的匹配方法（副本）。
func MethodsFor(t attributes.ValueType) []MatchMethod {
	spec, ok := methodTable[t]
	if !ok {
		return nil
	}
	out := make([]MatchMethod, len(spec.methods))
	copy(out, spec.methods)
	return out
}

// DefaultMethod 返回指定值类型的默认匹配方法。
func DefaultMethod(t attributes.ValueType) MatchMethod {
	if spec, ok := methodTable[t]; ok {
		return spec.defaultMethod
	}
	return MethodFull
}

// DefaultFormat 返回指定值类型的默认格式。
func DefaultFormat(t attributes.ValueType) Format {
	if spec, ok := methodTable[t]; ok {
		return spec.defaultFormat
	}
	return FormatPlain
}

func methodAllowed(t attributes.ValueType, m MatchMethod) bool {
	for _, x := range MethodsFor(t) {
		if x == m {
			return true
		}
	}
	return false
}

// canonValue 是属性的规范化值。判定阶段只处理这一种表示，避免在每次比较里重复做
// 类型断言与转换。
type canonValue struct {
	text    string
	bytes   []byte
	num     uint64
	signed  int64
	boolean bool
	set     []string
	ip      net.IP
	netw    *net.IPNet
}

// compiledObject 是预编译后的匹配对象。编译期完成三件事：参数补默认值、
// 字面量解析、正则预编译 —— 求值阶段不留任何解析工作。
type compiledObject struct {
	def      attributes.Def
	object   MatchObject
	method   MatchMethod
	format   Format
	valueTyp attributes.ValueType

	text   string
	texts  []string
	bytes  []byte
	num    uint64
	nums   map[uint64]bool
	signed int64
	signs  map[int64]bool
	boolv  bool
	lo     uint64
	hi     uint64
	loSet  bool
	hiSet  bool
	ip     net.IP
	netw   *net.IPNet
	nets   []*net.IPNet
	re     *regexp.Regexp
}

// uint64 上界常量。
const maxUint64 = ^uint64(0)

// compileObject 校验并预编译单个匹配对象。
func compileObject(def attributes.Def, obj MatchObject, where string) (*compiledObject, error) {
	if !def.Type.Valid() {
		return nil, fmt.Errorf("%s: 属性 %s 的值类型 %q 未登记", where, def.ID, def.Type)
	}
	c := &compiledObject{def: def, object: obj, valueTyp: def.Type}

	c.method = obj.MatchMethod
	if c.method == "" {
		c.method = DefaultMethod(def.Type)
	}
	if !c.method.Valid() {
		return nil, fmt.Errorf("%s: 属性 %s 的匹配方法 %q 未登记（可用：%s）",
			where, def.ID, obj.MatchMethod, joinMethods(MethodsFor(def.Type)))
	}
	if !methodAllowed(def.Type, c.method) {
		return nil, fmt.Errorf("%s: 属性 %s（类型 %s）不支持匹配方法 %q（可用：%s）",
			where, def.ID, def.Type, c.method, joinMethods(MethodsFor(def.Type)))
	}

	c.format = obj.Format
	if c.format == "" {
		c.format = DefaultFormat(def.Type)
	}
	if !c.format.Valid() {
		return nil, fmt.Errorf("%s: 属性 %s 的格式 %q 未登记（可用：%s）",
			where, def.ID, obj.Format, joinFormats())
	}
	// hex / base64 只对字节型有意义：对文本型做十六进制解码，多半是把
	// 「匹配十六进制字符串」与「匹配字节」搞混了，这里直接拒绝而不是猜测。
	if (c.format == FormatHex || c.format == FormatBase64) && def.Type != attributes.ValueTypeBytes {
		return nil, fmt.Errorf("%s: 属性 %s（类型 %s）不能使用格式 %q —— "+
			"hex/base64 仅用于 bytes 型属性", where, def.ID, def.Type, c.format)
	}

	if strings.TrimSpace(obj.Expression) == "" {
		return nil, fmt.Errorf("%s: 属性 %s 的表达式为空", where, def.ID)
	}
	if err := c.parseLiteral(obj.Expression); err != nil {
		return nil, fmt.Errorf("%s: 属性 %s 表达式 %q 非法: %w", where, def.ID, obj.Expression, err)
	}
	return c, nil
}

// parseLiteral 按值类型与方法解析表达式字面量。
func (c *compiledObject) parseLiteral(expr string) error {
	switch c.valueTyp {
	case attributes.ValueTypeBytes:
		parts := splitSet(expr)
		if len(parts) > 1 && c.method != MethodSet {
			return fmt.Errorf("表达式含 %d 个取值，但匹配方法为 %q —— 多值请使用 match_method=set",
				len(parts), c.method)
		}
		if c.method == MethodSet {
			// 字节型集合：以「等长前缀集合」实现，求值时逐个比对。
			for _, p := range parts {
				b, err := decodeBytes(p, c.format)
				if err != nil {
					return fmt.Errorf("集合项 %q 解码失败: %w", p, err)
				}
				if len(b) == 0 {
					return fmt.Errorf("集合项 %q 解码后为空", p)
				}
				c.texts = append(c.texts, string(b))
			}
			return nil
		}
		raw, err := decodeBytes(expr, c.format)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			return fmt.Errorf("解码后为空")
		}
		c.bytes = raw

	case attributes.ValueTypeString, attributes.ValueTypeEnum:
		if c.method == MethodRegex {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("正则编译失败: %w", err)
			}
			c.re = re
			c.text = expr
			return nil
		}
		if c.method == MethodSet {
			parts := splitSet(expr)
			if len(parts) == 0 {
				return fmt.Errorf("集合为空")
			}
			for _, p := range parts {
				c.texts = append(c.texts, normalizeText(p, c.format))
			}
			return nil
		}
		c.text = normalizeText(expr, c.format)

	case attributes.ValueTypeIP, attributes.ValueTypeIPPrefix:
		return c.parseIPLiteral(expr)

	case attributes.ValueTypePort, attributes.ValueTypeU8, attributes.ValueTypeU16,
		attributes.ValueTypeU32, attributes.ValueTypeU64, attributes.ValueTypeTimeMs:
		return c.parseUintLiteral(expr)

	case attributes.ValueTypeI64:
		return c.parseIntLiteral(expr)

	case attributes.ValueTypeBool:
		v, err := strconv.ParseBool(strings.TrimSpace(expr))
		if err != nil {
			return fmt.Errorf("布尔表达式应取 true/false")
		}
		c.boolv = v

	case attributes.ValueTypeStringSet:
		parts := splitSet(expr)
		if len(parts) == 0 {
			return fmt.Errorf("集合为空")
		}
		for _, p := range parts {
			c.texts = append(c.texts, normalizeText(p, c.format))
		}

	default:
		return fmt.Errorf("值类型 %q 尚无字面量解析规则", c.valueTyp)
	}
	return nil
}

func (c *compiledObject) parseIPLiteral(expr string) error {
	parts := splitSet(expr)
	if len(parts) > 1 && c.method != MethodSet {
		return fmt.Errorf("表达式含 %d 个取值，但匹配方法为 %q —— 多值请使用 match_method=set",
			len(parts), c.method)
	}
	if c.method == MethodSet {
		for _, p := range parts {
			n, err := parseNetOrIP(p)
			if err != nil {
				return fmt.Errorf("集合项 %q 既不是 IP 也不是网段: %w", p, err)
			}
			c.nets = append(c.nets, n)
		}
		return nil
	}
	e := strings.TrimSpace(expr)
	if ip := net.ParseIP(e); ip != nil {
		c.ip = ip
		return nil
	}
	_, n, err := net.ParseCIDR(e)
	if err != nil {
		if strings.Contains(e, "/") {
			return fmt.Errorf("既不是合法 IP 也不是合法 CIDR —— " +
				"若意在按网段匹配，请使用 match_method=cidr 或 set")
		}
		return fmt.Errorf("既不是 IP 也不是 CIDR")
	}
	c.netw = n
	return nil
}

// looksLikeRange 判断表达式是否形如区间（含 .. 或以比较符开头）。
func looksLikeRange(expr string) bool {
	e := strings.TrimSpace(expr)
	if strings.Contains(e, "..") {
		return true
	}
	for _, prefix := range []string{">=", "<=", ">", "<"} {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func (c *compiledObject) parseUintLiteral(expr string) error {
	if c.method == MethodSet {
		parts := splitSet(expr)
		if len(parts) == 0 {
			return fmt.Errorf("集合为空")
		}
		c.nums = make(map[uint64]bool, len(parts))
		for _, p := range parts {
			n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64)
			if err != nil {
				return fmt.Errorf("集合项 %q 不是无符号整数", p)
			}
			c.nums[n] = true
		}
		return nil
	}
	if c.method == MethodRange {
		lo, hi, loSet, hiSet, err := parseRange(expr)
		if err != nil {
			return err
		}
		c.lo, c.hi, c.loSet, c.hiSet = lo, hi, loSet, hiSet
		return nil
	}
	n, err := strconv.ParseUint(strings.TrimSpace(expr), 10, 64)
	if err != nil {
		// 区间表达式配 full 方法是最常见的手误：报错时给出可直接照做的修复建议，
		// 比只说「不是整数」有用得多。
		if looksLikeRange(expr) {
			return fmt.Errorf("不是无符号整数（表达式形如区间，请指定 match_method=range；" +
				"多值枚举请用 match_method=set）")
		}
		return fmt.Errorf("不是无符号整数")
	}
	c.num = n
	return nil
}

func (c *compiledObject) parseIntLiteral(expr string) error {
	if c.method == MethodSet {
		parts := splitSet(expr)
		if len(parts) == 0 {
			return fmt.Errorf("集合为空")
		}
		c.signs = make(map[int64]bool, len(parts))
		for _, p := range parts {
			n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
			if err != nil {
				return fmt.Errorf("集合项 %q 不是整数", p)
			}
			c.signs[n] = true
		}
		return nil
	}
	if c.method == MethodRange {
		lo, hi, loSet, hiSet, err := parseSignedRange(expr)
		if err != nil {
			return err
		}
		// i64 区间：有符号端点映射到无符号端点承载，避免再开一套字段；
		// 映射是双射（int64 -> uint64 的补码位移），比较时反向映射回来。
		if loSet {
			c.lo, c.loSet = uint64(lo), true
		}
		if hiSet {
			c.hi, c.hiSet = uint64(hi), true
		}
		return nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(expr), 10, 64)
	if err != nil {
		return fmt.Errorf("不是有符号整数")
	}
	c.signed = n
	return nil
}

// decodeBytes 按格式把表达式解码为字节。
func decodeBytes(expr string, f Format) ([]byte, error) {
	switch f {
	case FormatHex:
		clean := strings.Map(func(r rune) rune {
			if r == ':' || r == ' ' || r == '-' || r == '\t' {
				return -1
			}
			return r
		}, expr)
		return hex.DecodeString(clean)
	case FormatBase64:
		return base64.StdEncoding.DecodeString(strings.TrimSpace(expr))
	case FormatPlain, FormatUncase, FormatLower:
		return []byte(expr), nil
	}
	return nil, fmt.Errorf("格式 %q 不支持字节解码", f)
}

// normalizeText 按格式归一化文本。
func normalizeText(s string, f Format) string {
	switch f {
	case FormatUncase, FormatLower:
		return strings.ToLower(s)
	default:
		return s
	}
}

// splitSet 解析集合表达式：JSON 数组或逗号分隔。
//
// 两种都支持的理由：JSON 数组形式能表达含逗号的元素（少见但存在），逗号形式在规则
// 文件里更易读。以首个非空白字符是否为 '[' 区分，不做混用猜测。JSON 解析失败时
// 退回「整串视为单元素」，由后续字面量校验给出更具体的错误。
func splitSet(expr string) []string {
	t := strings.TrimSpace(expr)
	if strings.HasPrefix(t, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(t), &arr); err != nil {
			return []string{t}
		}
		return arr
	}
	parts := strings.Split(t, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseNetOrIP 把表达式解析为网段（单个 IP 视为 /32 或 /128）。
func parseNetOrIP(expr string) (*net.IPNet, error) {
	expr = strings.TrimSpace(expr)
	if strings.Contains(expr, "/") {
		_, n, err := net.ParseCIDR(expr)
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	ip := net.ParseIP(expr)
	if ip == nil {
		return nil, fmt.Errorf("无效 IP")
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// parseRange 解析无符号区间：lo..hi / lo.. / ..hi / >=lo / <=hi / >lo / <hi。
//
// 支持比较符号形式是为了贴合规则作者的直觉；两种形式最终都归一为闭区间端点，
// 开区间通过端点加减 1 实现，并显式处理 0 与 maxUint64 的回绕。
func parseRange(expr string) (lo, hi uint64, loSet, hiSet bool, err error) {
	e := strings.TrimSpace(expr)
	for _, prefix := range []string{">=", "<=", ">", "<"} {
		if !strings.HasPrefix(e, prefix) {
			continue
		}
		body := strings.TrimSpace(e[len(prefix):])
		n, perr := strconv.ParseUint(body, 10, 64)
		if perr != nil {
			return 0, 0, false, false, fmt.Errorf("区间端点 %q 不是无符号整数", body)
		}
		switch prefix {
		case ">=":
			return n, 0, true, false, nil
		case "<=":
			return 0, n, false, true, nil
		case ">":
			if n == maxUint64 {
				return 0, 0, false, false, fmt.Errorf("区间 >%d 为空", n)
			}
			return n + 1, 0, true, false, nil
		default: // "<"
			if n == 0 {
				return 0, 0, false, false, fmt.Errorf("区间 <0 为空")
			}
			return 0, n - 1, false, true, nil
		}
	}
	parts := strings.SplitN(e, "..", 2)
	if len(parts) != 2 {
		return 0, 0, false, false, fmt.Errorf("区间应形如 lo..hi / lo.. / ..hi")
	}
	if s := strings.TrimSpace(parts[0]); s != "" {
		n, perr := strconv.ParseUint(s, 10, 64)
		if perr != nil {
			return 0, 0, false, false, fmt.Errorf("区间下界 %q 不是无符号整数", s)
		}
		lo, loSet = n, true
	}
	if s := strings.TrimSpace(parts[1]); s != "" {
		n, perr := strconv.ParseUint(s, 10, 64)
		if perr != nil {
			return 0, 0, false, false, fmt.Errorf("区间上界 %q 不是无符号整数", s)
		}
		hi, hiSet = n, true
	}
	if loSet && hiSet && lo > hi {
		return 0, 0, false, false, fmt.Errorf("区间上下界颠倒（%d > %d）", lo, hi)
	}
	return lo, hi, loSet, hiSet, nil
}

// parseSignedRange 解析有符号区间，语义同 parseRange。
func parseSignedRange(expr string) (lo, hi int64, loSet, hiSet bool, err error) {
	parts := strings.SplitN(strings.TrimSpace(expr), "..", 2)
	if len(parts) != 2 {
		return 0, 0, false, false, fmt.Errorf("区间应形如 lo..hi / lo.. / ..hi")
	}
	if s := strings.TrimSpace(parts[0]); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			return 0, 0, false, false, fmt.Errorf("区间下界 %q 不是整数", s)
		}
		lo, loSet = n, true
	}
	if s := strings.TrimSpace(parts[1]); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			return 0, 0, false, false, fmt.Errorf("区间上界 %q 不是整数", s)
		}
		hi, hiSet = n, true
	}
	if loSet && hiSet && lo > hi {
		return 0, 0, false, false, fmt.Errorf("区间上下界颠倒（%d > %d）", lo, hi)
	}
	return lo, hi, loSet, hiSet, nil
}

func joinMethods(ms []MatchMethod) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, "/")
}

func joinFormats() string {
	parts := make([]string, 0, 5)
	for _, f := range AllFormats() {
		parts = append(parts, string(f))
	}
	return strings.Join(parts, "/")
}

// normalizeValue 把任意入参归一为 canonValue。
//
// 宽容度是刻意的：属性值可能来自共享内存（原生整型）、控制面 JSON（数字一律 float64）
// 或离线回放（字符串）。归一化集中在这里，判定路径上不再做类型分支。
func normalizeValue(def attributes.Def, raw any) (canonValue, error) {
	var cv canonValue
	switch def.Type {
	case attributes.ValueTypeString, attributes.ValueTypeEnum, attributes.ValueTypeTimeMs:
		s, ok := asStringValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望文本，收到 %T", def.ID, raw)
		}
		cv.text = s
	case attributes.ValueTypeBytes:
		b, ok := asBytesValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望字节串，收到 %T", def.ID, raw)
		}
		cv.bytes = b
	case attributes.ValueTypeIP:
		ip, ok := asIPValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望 IP，收到 %v", def.ID, raw)
		}
		cv.ip = ip
		cv.text = ip.String()
	case attributes.ValueTypeIPPrefix:
		ip, n, ok := asNetValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望 IP 或网段，收到 %v", def.ID, raw)
		}
		cv.ip, cv.netw = ip, n
	case attributes.ValueTypePort, attributes.ValueTypeU8, attributes.ValueTypeU16,
		attributes.ValueTypeU32, attributes.ValueTypeU64:
		n, ok := asUintValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望无符号整数，收到 %v", def.ID, raw)
		}
		cv.num = n
	case attributes.ValueTypeI64:
		n, ok := asIntValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望整数，收到 %v", def.ID, raw)
		}
		cv.signed = n
	case attributes.ValueTypeBool:
		b, ok := raw.(bool)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望布尔值，收到 %T", def.ID, raw)
		}
		cv.boolean = b
	case attributes.ValueTypeStringSet:
		set, ok := asStringSetValue(raw)
		if !ok {
			return cv, fmt.Errorf("属性 %s 期望字符串集合，收到 %T", def.ID, raw)
		}
		cv.set = set
	default:
		return cv, fmt.Errorf("属性 %s 的值类型 %q 尚无归一化规则", def.ID, def.Type)
	}
	return cv, nil
}

func asStringValue(raw any) (string, bool) {
	switch v := raw.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	case fmt.Stringer:
		return v.String(), true
	}
	return "", false
}

func asBytesValue(raw any) ([]byte, bool) {
	switch v := raw.(type) {
	case []byte:
		return v, true
	case string:
		// 字符串形态按十六进制解读：数据面与 pcap 样本都用十六进制传递载荷前缀。
		clean := strings.Map(func(r rune) rune {
			if r == ':' || r == ' ' || r == '-' {
				return -1
			}
			return r
		}, v)
		b, err := hex.DecodeString(clean)
		if err != nil {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

func asIPValue(raw any) (net.IP, bool) {
	switch v := raw.(type) {
	case net.IP:
		return v, true
	case string:
		ip := net.ParseIP(strings.TrimSpace(v))
		return ip, ip != nil
	}
	return nil, false
}

func asNetValue(raw any) (net.IP, *net.IPNet, bool) {
	switch v := raw.(type) {
	case *net.IPNet:
		return v.IP, v, true
	case string:
		s := strings.TrimSpace(v)
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, nil, false
			}
			return n.IP, n, true
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, nil, false
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, true
	}
	return nil, nil, false
}

func asUintValue(raw any) (uint64, bool) {
	switch v := raw.(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case uint:
		return uint64(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int32:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case float64:
		// JSON 解码后的数字一律是 float64；这里拒绝小数，避免 12.7 被静默截断为 12。
		if v < 0 || v != float64(uint64(v)) {
			return 0, false
		}
		return uint64(v), true
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func asIntValue(raw any) (int64, bool) {
	switch v := raw.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case uint64:
		if v > uint64(1<<63-1) {
			return 0, false
		}
		return int64(v), true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func asStringSetValue(raw any) ([]string, bool) {
	switch v := raw.(type) {
	case []string:
		return v, true
	case string:
		return []string{v}, true
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// Match 判定单个对象是否命中。
//
// 语义边界：raw 为 nil（属性缺失）时返回 (false, nil) —— 缺失不是错误，而是「条件
// 不成立」；只有值类型与属性类型冲突才返回 error。这一区分让「属性尚未计算」与
// 「规则写错了」在诊断信息里可分辨。
func (c *compiledObject) Match(raw any) (bool, error) {
	if raw == nil {
		return false, nil
	}
	cv, err := normalizeValue(c.def, raw)
	if err != nil {
		return false, err
	}
	return c.matchCanon(cv), nil
}

func (c *compiledObject) matchCanon(cv canonValue) bool {
	// 集合类型：方法语义与标量不同，单独处理。
	if c.valueTyp == attributes.ValueTypeStringSet {
		switch c.method {
		case MethodFull:
			return equalStringSets(cv.set, c.texts)
		case MethodContains:
			for _, got := range cv.set {
				g := normalizeText(got, c.format)
				for _, want := range c.texts {
					if strings.Contains(g, want) {
						return true
					}
				}
			}
			return false
		default: // MethodSet：交集非空
			for _, got := range cv.set {
				g := normalizeText(got, c.format)
				for _, want := range c.texts {
					if g == want {
						return true
					}
				}
			}
			return false
		}
	}

	switch c.valueTyp {
	case attributes.ValueTypeBytes:
		return matchBytes(cv.bytes, c)
	case attributes.ValueTypeIP, attributes.ValueTypeIPPrefix:
		return c.matchIP(cv)
	case attributes.ValueTypePort, attributes.ValueTypeU8, attributes.ValueTypeU16,
		attributes.ValueTypeU32, attributes.ValueTypeU64, attributes.ValueTypeTimeMs:
		return matchUint(cv.num, c)
	case attributes.ValueTypeI64:
		return matchInt(cv.signed, c)
	case attributes.ValueTypeBool:
		return cv.boolean == c.boolv
	default: // string / enum
		got := normalizeText(cv.text, c.format)
		return matchText(got, c)
	}
}

func (c *compiledObject) matchIP(cv canonValue) bool {
	gotIP := cv.ip
	if gotIP == nil && cv.netw != nil {
		gotIP = cv.netw.IP
	}
	switch c.method {
	case MethodSet:
		for _, n := range c.nets {
			if gotIP != nil && n.Contains(gotIP) {
				return true
			}
		}
		return false
	case MethodCIDR:
		// ip 型：值属于表达式网段；ip_prefix 型：值为表达式网段的子网（或同网段）。
		if cv.netw != nil {
			if c.netw != nil {
				return subnetOf(cv.netw, c.netw)
			}
			if c.ip != nil {
				return equalIPNet(cv.netw, c.ip)
			}
			return false
		}
		if c.netw != nil && gotIP != nil {
			return c.netw.Contains(gotIP)
		}
		if c.ip != nil && gotIP != nil {
			return c.ip.Equal(gotIP)
		}
		return false
	default: // MethodFull
		if c.ip != nil && gotIP != nil {
			return c.ip.Equal(gotIP)
		}
		if c.netw != nil && cv.netw != nil {
			return c.netw.String() == cv.netw.String()
		}
		return false
	}
}

// subnetOf 判断 child 是否落在 parent 内（含相等）：先要求掩码位数不小于 parent，
// 再判包含。只比较掩码长度而不比较包含关系会漏掉「同长度但不同网段」的情形。
func subnetOf(child, parent *net.IPNet) bool {
	if child == nil || parent == nil {
		return false
	}
	cOnes, cBits := child.Mask.Size()
	pOnes, pBits := parent.Mask.Size()
	if cOnes < 0 || pOnes < 0 || cBits != pBits {
		return false
	}
	if cOnes < pOnes {
		return false
	}
	return parent.Contains(child.IP)
}

func equalIPNet(n *net.IPNet, ip net.IP) bool {
	if n == nil || ip == nil {
		return false
	}
	ones, bits := n.Mask.Size()
	base := 32
	if ip.To4() == nil {
		base = 128
	}
	return bits == base && ones == base && n.IP.Equal(ip)
}

func matchText(got string, c *compiledObject) bool {
	switch c.method {
	case MethodFull:
		return got == c.text
	case MethodPrefix:
		return strings.HasPrefix(got, c.text)
	case MethodSuffix:
		return strings.HasSuffix(got, c.text)
	case MethodContains:
		return strings.Contains(got, c.text)
	case MethodRegex:
		return c.re.MatchString(got)
	case MethodSet:
		for _, want := range c.texts {
			if got == want {
				return true
			}
		}
		return false
	}
	return false
}

func matchBytes(got []byte, c *compiledObject) bool {
	switch c.method {
	case MethodFull:
		return string(got) == string(c.bytes)
	case MethodPrefix:
		return len(got) >= len(c.bytes) && string(got[:len(c.bytes)]) == string(c.bytes)
	case MethodSuffix:
		return len(got) >= len(c.bytes) && string(got[len(got)-len(c.bytes):]) == string(c.bytes)
	case MethodContains:
		return strings.Contains(string(got), string(c.bytes))
	case MethodSet:
		// 字节型集合按「等长前缀命中」实现：与 TSG 的载荷前缀签名（如
		// 「首包长度 54 且前 6 字节等于 000000016628」）用法一致。
		for _, want := range c.texts {
			w := []byte(want)
			if len(got) >= len(w) && string(got[:len(w)]) == string(w) {
				return true
			}
		}
		return false
	}
	return false
}

func matchUint(got uint64, c *compiledObject) bool {
	switch c.method {
	case MethodFull:
		return got == c.num
	case MethodSet:
		return c.nums[got]
	case MethodRange:
		if c.loSet && got < c.lo {
			return false
		}
		if c.hiSet && got > c.hi {
			return false
		}
		return true
	}
	return false
}

func matchInt(got int64, c *compiledObject) bool {
	switch c.method {
	case MethodFull:
		return got == c.signed
	case MethodSet:
		return c.signs[got]
	case MethodRange:
		if c.loSet && got < int64(c.lo) {
			return false
		}
		if c.hiSet && got > int64(c.hi) {
			return false
		}
		return true
	}
	return false
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	am := make(map[string]int, len(a))
	for _, s := range a {
		am[s]++
	}
	for _, s := range b {
		am[s]--
		if am[s] < 0 {
			return false
		}
	}
	return true
}
