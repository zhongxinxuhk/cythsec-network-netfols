// 本文件提供策略文件的读取。
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// policyDoc 是策略文件的顶层结构。
type policyDoc struct {
	Rules []Rule `json:"rules"`
}

// LoadFile 从 JSON 策略文件读取规则。
//
// 文件格式：
//
//	{"rules":[{"id":"r1","name":"默认放行","priority":10,"enabled":true,"expression":"..."}]}
//
// 选 JSON 而非 YAML 的理由：策略文件需要严格的结构校验，标准库
// encoding/json 已能提供字段级错误，且配置层已有一套极简 YAML，
// 再引入一个 YAML 变体只会增加歧义。
//
// maxRules > 0 时限制规则条数上限，超出即报错（防止误把巨型文件载入内存）。
// 解析采用 DisallowUnknownFields：字段名写错会立即失败，而非被静默忽略。
func LoadFile(path string, maxRules int) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取策略文件 %s 失败: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var doc policyDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("解析策略文件 %s 失败: %w", path, err)
	}
	if maxRules > 0 && len(doc.Rules) > maxRules {
		return nil, fmt.Errorf("策略文件 %s 含 %d 条规则，超过 max_rules=%d",
			path, len(doc.Rules), maxRules)
	}
	return doc.Rules, nil
}
