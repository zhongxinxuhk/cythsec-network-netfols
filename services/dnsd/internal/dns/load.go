// 本文件提供区域文件的读取。
package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// zoneDoc 是区域文件的顶层结构。
type zoneDoc struct {
	Zones []Zone `json:"zones"`
}

// LoadFile 从 JSON 区域文件读取区域。
//
// 文件格式：
//
//	{"zones":[{"name":"example.com","records":[{"name":"www","type":"A","ttl":300,"value":"192.0.2.1"}]}]}
//
// 选 JSON 而非 RFC 1035 master file 格式的理由：本阶段目标是固定数据模型与
// 控制面接口，master file 的解析（$TTL、$ORIGIN、括号续行、转义、类型特定
// 语法）是一项独立且体量可观的工作，属于后续里程碑。用 JSON 能让载入路径
// 立刻可测试，且不与将来真正的 zone 解析器产生语义混淆。
//
// maxZones > 0 时限制区域数上限，超出即报错（防止误把巨型文件载入内存）。
// 解析采用 DisallowUnknownFields：字段名写错会立即失败，而非被静默忽略。
func LoadFile(path string, maxZones int) ([]Zone, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取区域文件 %s 失败: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var doc zoneDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("解析区域文件 %s 失败: %w", path, err)
	}
	if maxZones > 0 && len(doc.Zones) > maxZones {
		return nil, fmt.Errorf("区域文件 %s 含 %d 个区域，超过 max_zones=%d",
			path, len(doc.Zones), maxZones)
	}
	return doc.Zones, nil
}
