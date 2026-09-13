// Package configutil 提供各服务共用的配置读取工具。
//
// 设计约束：只依赖标准库。仓库要求各 Go 服务在 GOPROXY=off 的离线环境下
// 仍可 `go build`，因此不引入任何第三方 YAML 库，改为自实现「仅顶层
// key: value」的极简解析。该子集足以覆盖各服务 configs/config.yaml 的形态。
//
// 各服务的配置优先级统一为（高 -> 低）：
//
//	命令行 flag > 环境变量 > YAML 文件 > 内置默认值
//
// 本包只负责后三层的取值与容错解析，flag 层由各服务自行处理。
package configutil

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Map 是从 YAML 文件解析出的顶层键值映射。键与值均为去除首尾空白后的字符串。
type Map map[string]string

// Get 返回键对应的值；不存在时返回默认值。
func (m Map) Get(key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

// Duration 返回解析后的时长；键缺失或解析失败时返回默认值。
func (m Map) Duration(key string, def time.Duration) time.Duration {
	v, ok := m[key]
	if !ok || v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

// Bool 返回布尔值；键缺失或解析失败时返回默认值。
func (m Map) Bool(key string, def bool) bool {
	v, ok := m[key]
	if !ok || v == "" {
		return def
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return def
}

// Int 返回整数；键缺失或解析失败时返回默认值。
func (m Map) Int(key string, def int) int {
	v, ok := m[key]
	if !ok || v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// List 返回按逗号切分的切片；键缺失时返回默认值。
func (m Map) List(key string, def []string) []string {
	v, ok := m[key]
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return SplitList(v)
}

// LoadYAML 读取并解析极简 YAML 文件。
//
// 文件不存在时返回空 Map 与 nil —— 各服务的 configs/config.yaml 属可选项，
// 缺失不应阻断启动。其他读取错误会原样返回。
func LoadYAML(path string) (Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Map{}, nil
		}
		return nil, err
	}
	return ParseYAML(data), nil
}

// ParseYAML 解析极简 YAML：仅顶层 `key: value`，忽略空行与整行 `#` 注释。
// 值两侧的单/双引号会被剥离；不支持行内注释与嵌套结构。
func ParseYAML(data []byte) Map {
	m := make(Map)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, "\"'")
		if key != "" {
			m[key] = val
		}
	}
	return m
}

// SplitList 按逗号切分并丢弃空白项。
func SplitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// FromEnv 读取带服务前缀的环境变量。prefix 形如 "ROUTERD"，
// key 形如 "listen_addr"，则实际读取 ROUTERD_LISTEN_ADDR。
// 未设置或为空串时返回 ("", false)。
func FromEnv(prefix, key string) (string, bool) {
	v := os.Getenv(strings.ToUpper(prefix) + "_" + strings.ToUpper(key))
	if v == "" {
		return "", false
	}
	return v, true
}

// EnvString 读取环境变量，未设置时返回默认值。
func EnvString(prefix, key, def string) string {
	if v, ok := FromEnv(prefix, key); ok {
		return v
	}
	return def
}

// EnvBool 读取布尔环境变量，未设置或解析失败时返回默认值。
func EnvBool(prefix, key string, def bool) bool {
	v, ok := FromEnv(prefix, key)
	if !ok {
		return def
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return def
}

// EnvDuration 读取时长环境变量，未设置或解析失败时返回默认值。
func EnvDuration(prefix, key string, def time.Duration) time.Duration {
	v, ok := FromEnv(prefix, key)
	if !ok {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

// EnvInt 读取整数环境变量，未设置或解析失败时返回默认值。
func EnvInt(prefix, key string, def int) int {
	v, ok := FromEnv(prefix, key)
	if !ok {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// EnvList 读取逗号分隔的列表环境变量，未设置时返回默认值。
func EnvList(prefix, key string, def []string) []string {
	v, ok := FromEnv(prefix, key)
	if !ok {
		return def
	}
	return SplitList(v)
}
