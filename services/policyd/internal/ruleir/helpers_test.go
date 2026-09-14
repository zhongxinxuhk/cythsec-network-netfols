// helpers_test.go —— 包内共享的测试夹具。
package ruleir

import (
	"sort"
	"strings"
	"testing"
)

// diagnoseCodes 抽取诊断码列表（排序后），用于断言"报了哪几类问题"。
func diagnoseCodes(diags []Diagnostic) []string {
	out := make([]string, 0, len(diags))
	for _, d := range diags {
		out = append(out, d.Code)
	}
	sort.Strings(out)
	return out
}

// hasCode 判断诊断集合中是否存在指定诊断码。
func hasCode(diags []Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

// countCode 统计指定诊断码出现次数。
func countCode(diags []Diagnostic, code string) int {
	n := 0
	for _, d := range diags {
		if d.Code == code {
			n++
		}
	}
	return n
}

// messageOf 返回指定诊断码的首条消息，便于断言消息内容。
func messageOf(diags []Diagnostic, code string) string {
	for _, d := range diags {
		if d.Code == code {
			return d.Message
		}
	}
	return ""
}

// compileSingleRule 编译单条规则所在的表，返回全部诊断。
func compileSingleRule(t *testing.T, r Rule, mode DeployMode) []Diagnostic {
	t.Helper()
	ct := Compile(&Table{Name: "T", Rules: []Rule{r}}, CompileOptions{Mode: mode})
	return ct.Diagnostics
}

// compileTable 编译整张表（要求无阻塞级诊断，否则直接失败）。
func compileTable(t *testing.T, tbl *Table, mode DeployMode) *CompiledTable {
	t.Helper()
	ct := Compile(tbl, CompileOptions{Mode: mode})
	if ct.HasErrors() {
		t.Fatalf("编译意外失败:\n  %s", joinDiagnostics(ct.Errors()))
	}
	return ct
}

func joinDiagnostics(diags []Diagnostic) string {
	lines := make([]string, 0, len(diags))
	for _, d := range diags {
		lines = append(lines, d.String())
	}
	return strings.Join(lines, "\n  ")
}

// baseRule 返回一条用于改写的合法规则。
func baseRule(uuid string) Rule {
	return Rule{
		UUID:            uuid,
		Name:            uuid,
		Enabled:         true,
		EvaluationOrder: 10,
		Conditions: []Condition{{
			Attribute: "ATTR_SERVER_FQDN",
			Objects:   []MatchObject{{Expression: "blocked.example", MatchMethod: MethodFull, Format: FormatUncase}},
		}},
		Action: Action{
			Kind:   ActionDeny,
			Params: ActionParams{SubActions: []SubAction{SubDropStream}},
		},
	}
}
