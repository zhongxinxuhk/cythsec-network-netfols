// store.go —— 规则加载后端抽象与版本化持有器。
//
// 对应 TSG/Maat 的三种加载模式（论文 §3.4）：Redis（热更新）、JSON 文件、
// IRIS（文件索引 + 数据表文件）。这三种模式的共同价值是**把「规则从哪来」与
// 「规则怎么匹配」解耦** —— 匹配逻辑只有一份，来源可以替换。
//
// 本项目的取舍：
//   - memory / json-file / index+datatable 三种后端用标准库实现；
//   - Redis 后端只保留接口与错误返回，不引入第三方客户端（与「零第三方依赖、
//     可离线构建」的工程约定一致）。要启用时先补客户端依赖，而不是先写半套实现。
//
// 在此之上，Registry 负责版本化：每次装载产生不可变快照（revision + 内容校验和），
// 保留上一版本以便回滚。对应 TSG 的 Redis 热更新模式 —— 热更新一旦推错，
// 没有回滚点的代价是被影响流量要等到人工修复。
package ruleir

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// 后端与装载相关的错误。
var (
	// ErrBackendUnavailable 表示该后端在当前构建下不可用（如缺第三方客户端）。
	ErrBackendUnavailable = errors.New("规则加载后端不可用")
	// ErrTableRejected 表示规则表存在阻塞级诊断，装载被拒绝。
	ErrTableRejected = errors.New("规则表被拒绝装载")
	// ErrNoPreviousSnapshot 表示没有可回滚的历史版本。
	ErrNoPreviousSnapshot = errors.New("没有可回滚的历史版本")
)

// Doc 是规则文件的顶层结构。
type Doc struct {
	// Version 是文件 schema 版本，便于未来格式演进时做兼容判断（0 表示未声明）。
	Version uint32 `json:"version,omitempty"`
	// Tables 是规则表列表。
	Tables []Table `json:"tables"`
}

// Store 是规则表加载后端。
type Store interface {
	// Name 返回后端名称，用于日志与指标标签。
	Name() string
	// Load 读取全部规则表。
	Load(ctx context.Context) ([]Table, error)
}

// decodeDoc 以严格模式解析规则 JSON：字段名写错立即失败，而不是被静默忽略。
//
// 之所以在所有后端共用它：规则文件里一个拼错的字段（如 match_methd）若被忽略，
// 结果是该条件退化为默认方法并可能放大匹配范围 —— 这正是「规则看起来生效了但范围不对」
// 的典型来源。宁可拒绝加载。
func decodeDoc(data []byte) ([]Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc Doc
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.Tables) == 0 {
		return nil, fmt.Errorf("规则文件不含任何规则表")
	}
	return doc.Tables, nil
}

// ---------------------------------------------------------------------------
// 后端实现

// MemoryStore 从内存中的表清单返回，用于测试与内嵌场景。
type MemoryStore struct {
	tables []Table
}

// NewMemoryStore 构造内存后端（深拷贝入参，避免调用方后续修改影响装载结果）。
func NewMemoryStore(tables ...Table) *MemoryStore {
	cp := make([]Table, 0, len(tables))
	for i := range tables {
		cp = append(cp, *tables[i].Clone())
	}
	return &MemoryStore{tables: cp}
}

// Name 返回后端名称。
func (s *MemoryStore) Name() string { return "memory" }

// Load 返回内存中的规则表副本。
func (s *MemoryStore) Load(ctx context.Context) ([]Table, error) {
	out := make([]Table, 0, len(s.tables))
	for i := range s.tables {
		out = append(out, *s.tables[i].Clone())
	}
	return out, nil
}

// FileStore 从单个 JSON 文件加载全部规则表。
type FileStore struct {
	path string
	// maxTables > 0 时限制表数量，防止误把超大文件载入。
	maxTables int
}

// NewFileStore 构造单文件后端。
func NewFileStore(path string, maxTables int) *FileStore {
	return &FileStore{path: path, maxTables: maxTables}
}

// Name 返回后端名称。
func (s *FileStore) Name() string { return "json-file" }

// Load 读取并解析规则文件。
func (s *FileStore) Load(ctx context.Context) ([]Table, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件 %s 失败: %w", s.path, err)
	}
	tables, err := decodeDoc(data)
	if err != nil {
		return nil, fmt.Errorf("解析规则文件 %s 失败: %w", s.path, err)
	}
	if s.maxTables > 0 && len(tables) > s.maxTables {
		return nil, fmt.Errorf("规则文件 %s 含 %d 张表，超过 max_tables=%d",
			s.path, len(tables), s.maxTables)
	}
	return tables, nil
}

// Path 返回后端文件路径。
func (s *FileStore) Path() string { return s.path }

// IndexDataTableStore 实现 TSG 的 IRIS 模式：一个索引文件列出各表对应的数据文件。
//
// 分表的收益在大规则集上才显现：索引文件可以被频繁读取（判断是否需要重载），
// 而体量大的数据表只在内容变化时读取。签名与规则库（十万级条目）属于这一类。
type IndexDataTableStore struct {
	indexPath string
	maxTables int
}

// indexDoc 是索引文件结构。
type indexDoc struct {
	// Tables 是表名到数据文件路径的映射，路径相对索引文件所在目录。
	Tables map[string]string `json:"tables"`
}

// NewIndexDataTableStore 构造索引+数据表后端。
func NewIndexDataTableStore(indexPath string, maxTables int) *IndexDataTableStore {
	return &IndexDataTableStore{indexPath: indexPath, maxTables: maxTables}
}

// Name 返回后端名称。
func (s *IndexDataTableStore) Name() string { return "index+datatable" }

// Load 先读索引，再逐个读取数据表文件。
func (s *IndexDataTableStore) Load(ctx context.Context) ([]Table, error) {
	data, err := os.ReadFile(s.indexPath)
	if err != nil {
		return nil, fmt.Errorf("读取规则索引 %s 失败: %w", s.indexPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var idx indexDoc
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("解析规则索引 %s 失败: %w", s.indexPath, err)
	}
	if len(idx.Tables) == 0 {
		return nil, fmt.Errorf("规则索引 %s 未列出任何表", s.indexPath)
	}
	if s.maxTables > 0 && len(idx.Tables) > s.maxTables {
		return nil, fmt.Errorf("规则索引 %s 列出 %d 张表，超过 max_tables=%d",
			s.indexPath, len(idx.Tables), s.maxTables)
	}

	base := filepath.Dir(s.indexPath)
	names := make([]string, 0, len(idx.Tables))
	for name := range idx.Tables {
		names = append(names, name)
	}
	// 索引内的表按名称排序装载，保证 revision 与校验和的可复现性。
	sort.Strings(names)

	out := make([]Table, 0, len(names))
	for _, name := range names {
		rel := idx.Tables[name]
		path := rel
		if !filepath.IsAbs(rel) {
			path = filepath.Join(base, rel)
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取表 %s 的数据文件 %s 失败: %w", name, path, err)
		}
		tables, err := decodeDoc(buf)
		if err != nil {
			return nil, fmt.Errorf("解析表 %s 的数据文件 %s 失败: %w", name, path, err)
		}
		for i := range tables {
			if tables[i].Name == "" {
				tables[i].Name = name
			}
			out = append(out, tables[i])
		}
	}
	return out, nil
}

// RedisStore 是 TSG「Redis 热更新」模式的对应位。
//
// 刻意不实现：引入 Redis 客户端会打破「零第三方依赖、可离线构建」的工程约定，
// 而半套实现（能连不能重连、能读不懂协议）比没有实现更危险。需要热更新时，
// 优先用 index+datatable 后端的文件重载路径，或先补齐依赖再实现。
type RedisStore struct {
	// Addr 是 Redis 地址，仅用于错误信息展示。
	Addr string
}

// Name 返回后端名称。
func (s *RedisStore) Name() string { return "redis" }

// Load 始终返回 ErrBackendUnavailable。
func (s *RedisStore) Load(ctx context.Context) ([]Table, error) {
	return nil, fmt.Errorf("%w: redis 后端（addr=%s）尚未实现 —— "+
		"需先引入客户端依赖并补齐重连与超时语义", ErrBackendUnavailable, s.Addr)
}

// ---------------------------------------------------------------------------
// 版本化持有器

// Version 是一次装载的版本信息。
type Version struct {
	// Revision 单调递增，仅在装载被接受时递增。
	Revision uint64 `json:"revision"`
	// Checksum 是规则内容的 SHA-256，用于判断内容是否真的变化。
	Checksum string `json:"checksum"`
	// Source 是后端名称。
	Source string `json:"source"`
	// LoadedAt 是装载时间。
	LoadedAt time.Time `json:"loaded_at"`
}

// Snapshot 是一次装载产生的不可变快照。
type Snapshot struct {
	Version     Version                   `json:"version"`
	Tables      map[string]*CompiledTable `json:"tables"`
	Diagnostics []Diagnostic              `json:"diagnostics"`
	// engines 是每表的判定引擎缓存，属运行期派生状态，不参与序列化。
	engines map[string]*Engine
}

// TableNames 按字典序返回快照内的表名。
func (s *Snapshot) TableNames() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.Tables))
	for name := range s.Tables {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// HasErrors 表示快照中是否存在阻塞级诊断。
func (s *Snapshot) HasErrors() bool {
	if s == nil {
		return false
	}
	for _, t := range s.Tables {
		if t.HasErrors() {
			return true
		}
	}
	return false
}

// Engine 返回指定表的判定引擎；表不存在时返回 nil。
func (s *Snapshot) Engine(table string) *Engine {
	if s == nil {
		return nil
	}
	return s.engines[table]
}

// Registry 是规则表的版本化持有器，并发安全。
type Registry struct {
	mu       sync.RWMutex
	current  *Snapshot
	previous *Snapshot
}

// NewRegistry 构造空注册表。
func NewRegistry() *Registry { return &Registry{} }

// Current 返回当前快照（可能为 nil）。
func (r *Registry) Current() *Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// Previous 返回上一版本快照（可能为 nil）。
func (r *Registry) Previous() *Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.previous
}

// Install 编译并安装一批规则表。
//
// 语义要点：
//  1. **先编译后替换**：任何表存在阻塞级诊断时整体拒绝，当前版本继续生效 ——
//     不允许「部分表更新成功」这种中间态。
//  2. **内容未变则不产生新版本**：以校验和判定，避免定时重载把 revision 刷成噪声。
//  3. **保留上一版本**：回滚是热更新的必要配套（见 Rollback）。
func (r *Registry) Install(tables []Table, opts CompileOptions, source string) (*Snapshot, error) {
	if len(tables) == 0 {
		return nil, fmt.Errorf("装载的规则表为空")
	}

	compiled := make(map[string]*CompiledTable, len(tables))
	diags := make([]Diagnostic, 0)
	for i := range tables {
		t := tables[i]
		name := t.Name
		if name == "" {
			return nil, fmt.Errorf("第 %d 张规则表缺少 name（表名是判定与审计的定位键）", i)
		}
		if _, dup := compiled[name]; dup {
			return nil, fmt.Errorf("规则表名重复: %s", name)
		}
		ct := Compile(&t, opts)
		diags = append(diags, ct.Diagnostics...)
		compiled[name] = ct
	}

	checksum, err := checksumTables(tables)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.current != nil && r.current.Version.Checksum == checksum {
		// 内容未变：复用当前快照，但把本次诊断带上，便于调用方仍能展示问题。
		cur := *r.current
		cur.Diagnostics = diags
		return &cur, nil
	}

	rejected := make([]Diagnostic, 0)
	for _, d := range diags {
		if d.Severity == SeverityError {
			rejected = append(rejected, d)
		}
	}
	if len(rejected) > 0 {
		msgs := make([]string, 0, len(rejected))
		for _, d := range rejected {
			msgs = append(msgs, d.String())
		}
		return nil, fmt.Errorf("%w（%d 条阻塞级诊断）：\n  %s",
			ErrTableRejected, len(rejected), joinLines(msgs))
	}

	revision := uint64(1)
	if r.current != nil {
		revision = r.current.Version.Revision + 1
	}
	snap := &Snapshot{
		Version: Version{
			Revision: revision,
			Checksum: checksum,
			Source:   source,
			LoadedAt: time.Now().UTC(),
		},
		Tables:      compiled,
		Diagnostics: diags,
		engines:     make(map[string]*Engine, len(compiled)),
	}
	for name, ct := range compiled {
		snap.engines[name] = NewEngine(ct, EngineOptions{})
	}

	r.previous = r.current
	r.current = snap
	return snap, nil
}

// Rollback 回滚到上一版本，返回是否发生回滚。
//
// 回滚后 previous 置空：只保留一步历史，避免「连续回滚到任意历史点」这种难以审计的语义。
// 需要多版本历史时应由调用方把快照序列化到外部存储，而不是让内存持有任意历史。
func (r *Registry) Rollback() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.previous == nil {
		return false
	}
	r.current = r.previous
	r.previous = nil
	return true
}

// LoadAndInstall 从后端装载并安装，是 Store 与 Registry 的组合入口。
func LoadAndInstall(ctx context.Context, store Store, reg *Registry, opts CompileOptions) (*Snapshot, error) {
	if store == nil {
		return nil, fmt.Errorf("规则加载后端为 nil")
	}
	tables, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	return reg.Install(tables, opts, store.Name())
}

// checksumTables 计算规则表的规范校验和。
//
// 先按表名排序再编码，使「同一份规则的不同书写顺序」得到同一校验和 —— 否则定时重载
// 会因排序差异反复产生新版本。
func checksumTables(tables []Table) (string, error) {
	ordered := make([]Table, 0, len(tables))
	for i := range tables {
		ordered = append(ordered, *tables[i].Clone())
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	for i := range ordered {
		sort.SliceStable(ordered[i].Rules, func(a, b int) bool {
			if ordered[i].Rules[a].EvaluationOrder != ordered[i].Rules[b].EvaluationOrder {
				return ordered[i].Rules[a].EvaluationOrder < ordered[i].Rules[b].EvaluationOrder
			}
			return ordered[i].Rules[a].UUID < ordered[i].Rules[b].UUID
		})
	}
	data, err := json.Marshal(Doc{Tables: ordered})
	if err != nil {
		return "", fmt.Errorf("规则校验和计算失败: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}
