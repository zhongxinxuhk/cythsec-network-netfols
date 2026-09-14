// attributes_test.go —— 属性字典的一致性测试。
//
// 本文件承担两个职责：
//  1. 校验生成物自身的不变量（查找往返、返回副本、类型合法、越界 panic 边界）；
//  2. **把真源纳入测试**：直接读取 configs/registry/attributes.json 并与生成表逐条比对。
//     仅靠 scripts/verify/check-attributes.sh 只能保证「生成物没被手工改过」，
//     却无法发现「生成表读起来自洽但与真源字段错位」这类问题 —— 这里补上。
package attributes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// registryPath 是属性字典真源相对于本包测试工作目录的位置。
func registryPath() string {
	return filepath.Join("..", "..", "..", "configs", "registry", "attributes.json")
}

// registryDoc 是真源文件的顶层结构（只声明测试用得到的字段）。
type registryDoc struct {
	Version    int                      `json:"version"`
	Types      map[string]string        `json:"types"`
	Scopes     map[string]string        `json:"scopes"`
	Stages     map[string]string        `json:"stages"`
	Attributes []map[string]interface{} `json:"attributes"`
}

func loadRegistry(t *testing.T) registryDoc {
	t.Helper()
	data, err := os.ReadFile(registryPath())
	if err != nil {
		t.Fatalf("读取属性字典真源失败: %v", err)
	}
	var doc registryDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("解析属性字典真源失败: %v", err)
	}
	return doc
}

func TestLookupRoundTrip(t *testing.T) {
	ids := IDs()
	if len(ids) == 0 {
		t.Fatal("属性表为空：生成物可疑")
	}
	for _, id := range ids {
		def, ok := Lookup(id)
		if !ok {
			t.Fatalf("Lookup(%q) 未命中，但该 ID 来自 IDs()", id)
		}
		if def.ID != id {
			t.Errorf("Lookup(%q).ID = %q，期望相同", id, def.ID)
		}
		if !def.Type.Valid() {
			t.Errorf("属性 %s 的值类型 %q 未登记", id, def.Type)
		}
		if !def.Scope.Valid() {
			t.Errorf("属性 %s 的作用域 %q 未登记", id, def.Scope)
		}
		if !def.Stage.Valid() {
			t.Errorf("属性 %s 的计算阶段 %q 未登记", id, def.Stage)
		}
		if def.Cost < 1 || def.Cost > 3 {
			t.Errorf("属性 %s 的代价 %d 越界（应为 1..3）", id, def.Cost)
		}
		if def.Source == "" || def.Desc == "" {
			t.Errorf("属性 %s 缺少 source 或 desc", id)
		}
		if def.Type.Description() == "" {
			t.Errorf("值类型 %q 缺少说明文本", def.Type)
		}
		if def.Scope.Description() == "" {
			t.Errorf("作用域 %q 缺少说明文本", def.Scope)
		}
		if def.Stage.Description() == "" {
			t.Errorf("计算阶段 %q 缺少说明文本", def.Stage)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("ATTR_NOT_REGISTERED"); ok {
		t.Error("未登记的属性标识不应命中")
	}
	if _, ok := Lookup(""); ok {
		t.Error("空标识不应命中")
	}
}

func TestMustLookupPanicsOnUnknown(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustLookup 对未登记标识应当 panic，否则调用点会拿到零值 Def 静默出错")
		}
	}()
	MustLookup("ATTR_NOT_REGISTERED")
}

func TestAllReturnsCopy(t *testing.T) {
	first := All()
	if len(first) != Count() {
		t.Fatalf("All() 长度 %d 与 Count() %d 不一致", len(first), Count())
	}
	original := first[0].ID
	first[0].ID = "已被调用方篡改"

	if got := All()[0].ID; got != original {
		t.Errorf("All() 返回了内部切片：调用方修改后内部值为 %q", got)
	}
	if def, ok := Lookup(original); !ok || def.ID != original {
		t.Errorf("查找 %q 失败，内部表已受调用方影响", original)
	}
}

func TestGeneratedMatchesRegistry(t *testing.T) {
	doc := loadRegistry(t)
	if doc.Version != RegistryVersion {
		t.Errorf("生成物版本 %d 与真源版本 %d 不一致", RegistryVersion, doc.Version)
	}

	defs := All()
	if len(defs) != len(doc.Attributes) {
		t.Fatalf("生成物 %d 条属性，真源 %d 条：需重新生成",
			len(defs), len(doc.Attributes))
	}

	// 逐条比对，且要求顺序一致 —— 顺序影响控制台与文档的展示，也影响
	// 「真源插入新属性后生成物是否同步」这一判断。
	for i, raw := range doc.Attributes {
		def := defs[i]
		want := map[string]string{
			"id":     asString(t, raw, "id"),
			"type":   asString(t, raw, "type"),
			"scope":  asString(t, raw, "scope"),
			"stage":  asString(t, raw, "stage"),
			"source": asString(t, raw, "source"),
			"desc":   asString(t, raw, "desc"),
		}
		if def.ID != want["id"] {
			t.Errorf("第 %d 条 ID：生成物 %q，真源 %q", i, def.ID, want["id"])
		}
		if string(def.Type) != want["type"] {
			t.Errorf("属性 %s 的 type：生成物 %q，真源 %q", def.ID, def.Type, want["type"])
		}
		if string(def.Scope) != want["scope"] {
			t.Errorf("属性 %s 的 scope：生成物 %q，真源 %q", def.ID, def.Scope, want["scope"])
		}
		if string(def.Stage) != want["stage"] {
			t.Errorf("属性 %s 的 stage：生成物 %q，真源 %q", def.ID, def.Stage, want["stage"])
		}
		if def.Source != want["source"] {
			t.Errorf("属性 %s 的 source：生成物 %q，真源 %q", def.ID, def.Source, want["source"])
		}
		if def.Desc != want["desc"] {
			t.Errorf("属性 %s 的 desc：生成物 %q，真源 %q", def.ID, def.Desc, want["desc"])
		}
		if cost, ok := raw["cost"].(float64); !ok || int(cost) != def.Cost {
			t.Errorf("属性 %s 的 cost：生成物 %d，真源 %v", def.ID, def.Cost, raw["cost"])
		}
	}
}

func asString(t *testing.T, raw map[string]interface{}, key string) string {
	t.Helper()
	v, ok := raw[key].(string)
	if !ok {
		t.Fatalf("真源字段 %q 缺失或不是字符串: %v", key, raw[key])
	}
	return v
}
