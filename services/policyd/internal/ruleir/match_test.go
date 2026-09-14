// match_test.go —— 匹配语义与格式归一化的行为测试。
//
// 测试用例刻意采用两类来源：
//  1. TSG/Maat 规则的实际形态（论文 Table 2 的 blocked.com、Table 4 的载荷前缀签名）；
//  2. 边界与误用形态（方法/类型不匹配、多值表达式、格式越界）—— 这些必须在编译期
//     报错，而不是在运行期静默不匹配。
package ruleir

import (
	"strings"
	"testing"

	"cythsec/services/pkg/attributes"
)

func mustDef(t *testing.T, id string) attributes.Def {
	t.Helper()
	def, ok := attributes.Lookup(id)
	if !ok {
		t.Fatalf("属性 %s 未登记，属性字典缺项", id)
	}
	return def
}

func compileOne(t *testing.T, attr string, obj MatchObject) (*compiledObject, error) {
	t.Helper()
	return compileObject(mustDef(t, attr), obj, "测试")
}

func mustCompileOne(t *testing.T, attr string, obj MatchObject) *compiledObject {
	t.Helper()
	co, err := compileOne(t, attr, obj)
	if err != nil {
		t.Fatalf("编译对象失败: %v", err)
	}
	return co
}

func mustMatch(t *testing.T, co *compiledObject, raw any, want bool) {
	t.Helper()
	got, err := co.Match(raw)
	if err != nil {
		t.Fatalf("Match(%v) 返回错误: %v", raw, err)
	}
	if got != want {
		t.Errorf("Match(%v) = %v，期望 %v（对象 %s）", raw, got, want, co.describe())
	}
}

func TestMatchTextSemantics(t *testing.T) {
	fqdn := attributes.ServerFQDN

	cases := []struct {
		name   string
		obj    MatchObject
		value  any
		expect bool
	}{
		{"full 忽略大小写", MatchObject{Expression: "blocked.com", MatchMethod: MethodFull, Format: FormatUncase}, "Blocked.COM", true},
		{"full 区分大小写", MatchObject{Expression: "blocked.com", MatchMethod: MethodFull, Format: FormatPlain}, "Blocked.COM", false},
		{"suffix 命中", MatchObject{Expression: ".com", MatchMethod: MethodSuffix}, "example.com", true},
		{"suffix 不命中更长后缀", MatchObject{Expression: ".com", MatchMethod: MethodSuffix}, "example.com.au", false},
		{"prefix 命中", MatchObject{Expression: "ads.", MatchMethod: MethodPrefix}, "ads.example.net", true},
		{"contains 命中", MatchObject{Expression: "track", MatchMethod: MethodContains}, "cdn-tracker.example", true},
		{"regex 命中", MatchObject{Expression: `^cdn[0-9]+\.`, MatchMethod: MethodRegex}, "cdn12.example.net", true},
		{"regex 不命中", MatchObject{Expression: `^cdn[0-9]+\.`, MatchMethod: MethodRegex}, "cdnx.example.net", false},
		{"set 逗号形式", MatchObject{Expression: "a.com,b.com", MatchMethod: MethodSet}, "B.COM", true},
		{"set JSON 形式", MatchObject{Expression: `["a.com","b.com"]`, MatchMethod: MethodSet}, "c.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			co := mustCompileOne(t, fqdn, tc.obj)
			mustMatch(t, co, tc.value, tc.expect)
		})
	}
}

func TestMatchDefaultsByValueType(t *testing.T) {
	// 文本型默认 full + uncase；bytes 型默认 prefix + hex。
	co := mustCompileOne(t, attributes.ServerFQDN, MatchObject{Expression: "Blocked.com"})
	if co.method != MethodFull || co.format != FormatUncase {
		t.Fatalf("文本型默认值错误：method=%s format=%s", co.method, co.format)
	}
	mustMatch(t, co, "BLOCKED.COM", true)

	co = mustCompileOne(t, attributes.FirstPayloadC2S, MatchObject{Expression: "000000016628"})
	if co.method != MethodPrefix || co.format != FormatHex {
		t.Fatalf("bytes 型默认值错误：method=%s format=%s", co.method, co.format)
	}
	// 对齐 TSG HideMe VPN 签名：首包载荷前 6 字节等于 00 00 00 01 66 28。
	mustMatch(t, co, "000000016628aabb", true)
	mustMatch(t, co, "000000019999", false)
}

func TestMatchBytesAcceptsByteSliceAndHexString(t *testing.T) {
	co := mustCompileOne(t, attributes.FirstPayloadC2S,
		MatchObject{Expression: "00:00:00:01:66:28", MatchMethod: MethodPrefix, Format: FormatHex})
	mustMatch(t, co, []byte{0x00, 0x00, 0x00, 0x01, 0x66, 0x28, 0xff}, true)
	mustMatch(t, co, "000000016628ff", true)
}

func TestMatchNumericSemantics(t *testing.T) {
	port := attributes.DstPort

	cases := []struct {
		name     string
		obj      MatchObject
		value    any
		expect   bool
		errMatch string
	}{
		{name: "full 命中", obj: MatchObject{Expression: "443"}, value: uint16(443), expect: true},
		{name: "full 不命中", obj: MatchObject{Expression: "443"}, value: 8443, expect: false},
		{name: "range 命中", obj: MatchObject{Expression: "1024..65535", MatchMethod: MethodRange}, value: 5000, expect: true},
		{name: "range 不命中", obj: MatchObject{Expression: "1024..65535", MatchMethod: MethodRange}, value: 80, expect: false},
		{name: ">= 命中", obj: MatchObject{Expression: ">=10000", MatchMethod: MethodRange}, value: 20000, expect: true},
		{name: "< 不命中", obj: MatchObject{Expression: "<1024", MatchMethod: MethodRange}, value: 1024, expect: false},
		{name: "set 命中", obj: MatchObject{Expression: "80,443,8080", MatchMethod: MethodSet}, value: 8080, expect: true},
		{name: "set 不命中", obj: MatchObject{Expression: "80,443,8080", MatchMethod: MethodSet}, value: 53, expect: false},
		{name: "JSON 浮点入参", obj: MatchObject{Expression: "443"}, value: float64(443), expect: true},
		{name: "字符串入参", obj: MatchObject{Expression: "443"}, value: "443", expect: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			co := mustCompileOne(t, port, tc.obj)
			mustMatch(t, co, tc.value, tc.expect)
		})
	}
}

func TestMatchIPSemantics(t *testing.T) {
	dst := attributes.DstIP

	co := mustCompileOne(t, dst, MatchObject{Expression: "10.0.0.0/8", MatchMethod: MethodCIDR})
	mustMatch(t, co, "10.1.2.3", true)
	mustMatch(t, co, "11.1.2.3", false)

	co = mustCompileOne(t, dst, MatchObject{Expression: "192.168.1.1", MatchMethod: MethodFull})
	mustMatch(t, co, "192.168.1.1", true)
	mustMatch(t, co, "192.168.1.2", false)

	// 集合形式直接对应 TSG 的「1,023 个 CDN IP 段」用例。
	co = mustCompileOne(t, dst, MatchObject{
		Expression: "192.0.2.0/24,198.51.100.0/24", MatchMethod: MethodSet})
	mustMatch(t, co, "198.51.100.7", true)
	mustMatch(t, co, "203.0.113.7", false)
}

func TestMatchPrefixValueSemantics(t *testing.T) {
	// ATTR_IOC_NET 是 ip_prefix 型：默认方法为 cidr，语义是「值为表达式的子网」。
	// 这一语义对应情报侧的真实用法：情报给出一个段，判定某个更具体的段是否落在其中。
	netAttr := attributes.IOCNet
	co := mustCompileOne(t, netAttr, MatchObject{Expression: "10.0.0.0/8"})
	mustMatch(t, co, "10.1.0.0/16", true)    // 子网落在 10/8 内
	mustMatch(t, co, "172.16.0.0/16", false) // 不在范围内
	// 单 IP 可视为 /32：命中范围
	mustMatch(t, co, "10.9.9.9", true)
	// 掩码比表达式更短（覆盖更宽）不应命中
	mustMatch(t, co, "10.0.0.0/4", false)
}

func TestMatchStringSetSemantics(t *testing.T) {
	san := attributes.TLSCertSAN
	co := mustCompileOne(t, san, MatchObject{Expression: "a.example,b.example"})
	mustMatch(t, co, []string{"x.example", "b.example"}, true)
	mustMatch(t, co, []string{"x.example"}, false)

	// contains：集合中任一元素包含表达式即为真。
	co = mustCompileOne(t, san, MatchObject{Expression: "example", MatchMethod: MethodContains})
	mustMatch(t, co, []string{"x.example.net"}, true)
	mustMatch(t, co, []string{"x.invalid"}, false)

	// full：集合完全相等（顺序无关）。
	co = mustCompileOne(t, san, MatchObject{Expression: "a,b", MatchMethod: MethodFull})
	mustMatch(t, co, []string{"b", "a"}, true)
	mustMatch(t, co, []string{"a"}, false)
}

func TestMatchBoolSemantics(t *testing.T) {
	df := attributes.IPDFBit
	co := mustCompileOne(t, df, MatchObject{Expression: "true"})
	mustMatch(t, co, true, true)
	mustMatch(t, co, false, false)
}

func TestMatchMissingAttributeIsNotError(t *testing.T) {
	co := mustCompileOne(t, attributes.ServerFQDN, MatchObject{Expression: "blocked.com"})
	got, err := co.Match(nil)
	if err != nil {
		t.Fatalf("属性缺失不应返回错误，得到 %v", err)
	}
	if got {
		t.Error("属性缺失时对象不应命中")
	}
}

func TestMatchTypeConflictIsError(t *testing.T) {
	co := mustCompileOne(t, attributes.DstPort, MatchObject{Expression: "443"})
	if _, err := co.Match("not-a-number"); err == nil {
		t.Error("值类型与属性类型冲突时应返回错误，而不是静默不匹配")
	}
}

func TestCompileObjectRejectsInvalidCombinations(t *testing.T) {
	cases := []struct {
		name     string
		attr     string
		obj      MatchObject
		errMatch string
	}{
		{
			name: "整数不支持正则", attr: attributes.DstPort,
			obj: MatchObject{Expression: `^4\d\d$`, MatchMethod: MethodRegex}, errMatch: "不支持匹配方法",
		},
		{
			name: "文本不支持十六进制格式", attr: attributes.ServerFQDN,
			obj: MatchObject{Expression: "6162", Format: FormatHex}, errMatch: "hex/base64 仅用于 bytes",
		},
		{
			name: "多值表达式需 set 方法", attr: attributes.DstIP,
			obj: MatchObject{Expression: "10.0.0.0/8,192.168.0.0/16"}, errMatch: "多值请使用 match_method=set",
		},
		{
			name: "非法 CIDR", attr: attributes.DstIP,
			obj: MatchObject{Expression: "10.0.0.0/33", MatchMethod: MethodCIDR}, errMatch: "既不是合法 IP 也不是合法 CIDR",
		},
		{
			name: "区间上下界颠倒", attr: attributes.DstPort,
			obj: MatchObject{Expression: "100..10", MatchMethod: MethodRange}, errMatch: "颠倒",
		},
		{
			name: "区间格式错误", attr: attributes.DstPort,
			obj: MatchObject{Expression: "100-200", MatchMethod: MethodRange}, errMatch: "区间应形如",
		},
		{
			name: "表达式为空", attr: attributes.ServerFQDN, obj: MatchObject{Expression: "  "}, errMatch: "表达式为空",
		},
		{
			name: "未登记的匹配方法", attr: attributes.ServerFQDN,
			obj: MatchObject{Expression: "a", MatchMethod: "glob"}, errMatch: "未登记",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileOne(t, tc.attr, tc.obj)
			if err == nil {
				t.Fatalf("期望编译失败，但成功了")
			}
			if !strings.Contains(err.Error(), tc.errMatch) {
				t.Fatalf("错误信息 %q 未包含 %q", err.Error(), tc.errMatch)
			}
		})
	}
}

func TestLiteralKeyUnifiesEquivalentWritings(t *testing.T) {
	// 同义写法应产生同一签名，否则冲突/冗余检测会被书写差异绕过。
	a := mustCompileOne(t, attributes.FirstPayloadC2S,
		MatchObject{Expression: "00:00:00:01:66:28", MatchMethod: MethodPrefix, Format: FormatHex})
	b := mustCompileOne(t, attributes.FirstPayloadC2S,
		MatchObject{Expression: "000000016628", MatchMethod: MethodPrefix, Format: FormatHex})
	if a.signature() != b.signature() {
		t.Errorf("同义字节字面量签名不同：%s vs %s", a.signature(), b.signature())
	}

	c := mustCompileOne(t, attributes.ServerFQDN, MatchObject{Expression: "A.com,b.com", MatchMethod: MethodSet})
	d := mustCompileOne(t, attributes.ServerFQDN, MatchObject{Expression: `["b.com","a.com"]`, MatchMethod: MethodSet})
	if c.signature() != d.signature() {
		t.Errorf("同义集合签名不同：%s vs %s", c.signature(), d.signature())
	}
}

func TestMethodTableCoverage(t *testing.T) {
	// 每个已登记的属性类型都必须有匹配方法表项，否则属性不可用（编译期会以
	// 「不支持匹配方法」暴露，但更早发现更好）。
	for _, def := range attributes.All() {
		if MethodsFor(def.Type) == nil {
			t.Errorf("属性 %s 的类型 %s 缺少匹配方法表项", def.ID, def.Type)
		}
		if !DefaultMethod(def.Type).Valid() {
			t.Errorf("属性 %s 的类型 %s 默认方法未登记", def.ID, def.Type)
		}
		if !DefaultFormat(def.Type).Valid() {
			t.Errorf("属性 %s 的类型 %s 默认格式未登记", def.ID, def.Type)
		}
	}
}
