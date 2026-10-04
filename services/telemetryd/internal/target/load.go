// 本文件提供抓取目标文件的读取。
package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// targetDoc 是目标文件的顶层结构。
type targetDoc struct {
	Targets []Target `json:"targets"`
}

// LoadFile 从 JSON 目标文件读取抓取目标。
//
// 文件格式：
//
//	{"targets":[{"name":"routerd","url":"http://127.0.0.1:8080/metrics","interval_seconds":15,"timeout_seconds":10,"enabled":true,"labels":{"env":"prod"}}]}
//
// 选 JSON 而非 YAML 的理由与其他服务一致：需要严格结构校验，
// 标准库 encoding/json 已能提供字段级错误。
//
// maxTargets > 0 时限制目标数上限，超出即报错。
// 解析采用 DisallowUnknownFields：字段名写错会立即失败，而非被静默忽略成
// 「启用了但用默认间隔」这类难以察觉的偏差。
func LoadFile(path string, maxTargets int) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取目标文件 %s 失败: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var doc targetDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("解析目标文件 %s 失败: %w", path, err)
	}
	if maxTargets > 0 && len(doc.Targets) > maxTargets {
		return nil, fmt.Errorf("目标文件 %s 含 %d 个目标，超过 max_targets=%d",
			path, len(doc.Targets), maxTargets)
	}
	return doc.Targets, nil
}
