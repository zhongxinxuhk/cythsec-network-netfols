# CythSec 接力文档（HANDOFF）

> 状态点：`4d62530` · 2026-10-02（AEST）
> 上一检查点：`fb031ef`（DPI 批次）、`d3c2b3a`（远端 master 基线）
> 主待办表：`docs/planning/BACKLOG.md`（349 任务 / 9 里程碑）
> ⚠ **待办表的控制平面部分已滞后于代码**，直接照它做会重复劳动 —— 见 §1 顶部。
> 本文件回答一个具体问题：**下一棒接手时，哪些事必须知道，否则会踩重复的坑。**

**本文件的三条硬约束**（其余内容都是解释）：

1. §8 里标了「理由」的，理由比结论重要——**先读理由再决定是否推翻**。
2. §6 是**诚实清单**。往报告或演示里抹平它，等于把已知风险藏起来。
3. §4.2 的**反向注入**是新增门禁的必做动作。绿色的「通过」和绿色的「没跑」长得一样。

---

## 1. 三十秒版本

数据平面（C++ 收包 → 共享内存环 → Rust 分析）已打通往返链路，本轮把 Rust 侧
「流量分析」从「Flow/Session 计数」推进到**能识别应用协议**：

| 能力 | 状态 | 落地位置 |
| --- | --- | --- |
| 深度包检测（TLS/JA3、DNS、HTTP） | ◐ 已落地，三方互证通过 | `dataplane/traffic-engine/src/dpi/` |
| TCP 乱序重组 + TCP 选项解析 | ◐ 已落地，三方互证通过 | `dataplane/traffic-engine/src/reassembly/` |
| 真实网卡抓包（Linux AF_PACKET / macOS BPF） | ◐ 编译与断言通过，**真抓包未验收** | `dataplane/packet-engine/src/backends/` |
| 跨语言共享环端到端 | ☑ 19 项断言通过 | `scripts/verify/e2e-shared-ring.sh` |
| 控制平面（Go 四服务） | ◐ 引擎内核已落地（约 9000 行源码 / 7000 行测试），**但待办表未同步** | `services/` |

> ⚠ **接手前必读的一条偏差**：`docs/planning/BACKLOG.md` 的**控制平面部分已明显滞后于代码**。
> 待办表把 `CYS-POL-001`（policyd 骨架）、`CYS-DNS-001`、`CYS-TEL-001`、整个 M4
> 里程碑都标着「⬜ 未开始」，但仓库里这些服务**已经存在且测试全过**（19 个 Go 测试包）。
> 成因已定位：这些实现由**并行协作者**在 `9748175` / `8e0fb03`（2026-09-14，16661 行）
> 落库，而那批提交**没有回写待办表**。
> **照 BACKLOG 去「落地 policyd 骨架」= 重复劳动。** 做控制平面前先读代码
> （见 §3），真实缺口见 §8。

**门禁实测状态**（2026-10-02 逐项复跑）：

| 门禁 | 结果 | 跑法 |
| --- | --- | --- |
| CTest | 6/6 通过 | `--cpp` |
| Rust 单测 | 158 项通过 | `--rust` |
| Go | 通过 | `--go` |
| 前端 vitest | 25 项通过（4 文件） | `cd web/console && npm test` ⚠ 见下 |
| 通道 ABI parity | 89 行一致 | `--parity`（须同时选 `--cpp --rust`） |
| DPI 的 tshark 核验 | 22 项一致（跳过 10 项已知例外） | `--dpi` |
| 重组的 tshark 核验 | 16 项一致（跳过 2 项已知例外） | `--reassembly` |
| 跨语言 e2e | 4 阶段 / 19 项断言通过 | `--e2e`（须同时选 `--cpp --rust`） |
| lint（格式 + 真源一致性） | 7 项全过 | `scripts/lint/lint-all.sh` |

> ⚠ **本机唯一必红的一项**：`test-all.sh --node` 里的 `npm ci` 会被环境的
> `safe-delete` 钩子拦下（它要删 `node_modules/.bin`，7884 个目标 > 阈值 50），
> 脚本把它包装成「npm ci 失败（可能需要网络）」——**这个提示是误导，不是网络问题**。
> 前端代码本身是绿的：`cd web/console && npm test` → 25 项通过。
> 详见 §7.1。**除这一项外，其余各栈单独跑均全绿**（含不带参数跑时的其余部分）。

待办表状态（`count-backlog.sh`）：349 任务 / 9 里程碑 —— 未开始 318 · 进行中 10 · 已完成 21。

---

## 2. 本批做了什么（含「为什么这么做」，避免下一棒改回去）

### 2.1 DPI 深度包检测（`fb031ef`）

**动因是用户的一句话**：「pcap 这个流量一大就不行了」。实测证据：
`src/backends/pcap_file.cpp` 在 open 时把**整个文件**读进
`std::vector<PacketBuffer>` —— 非流式、无界内存、不报丢包，省网 100G 物理上走不通。
本轮补的是**识别能力**这一侧（真正的流式采集属另一个任务）。

新增 `src/dpi/`，核心是**三级递进识别框架**：
端口给候选顺序（成本 0）→ 载荷特征逐个确认 → 兜底 unknown。

**四个必须延续的设计决定：**

1. **裁决语义用四态枚举，刻意不用 `Result`**
   `Identified / NeedMore / Malformed / Unknown`。
   理由：「不是我的协议（Rejected）」与「我的协议解析坏了（Malformed）」
   在 `Result` 里都只是 `Err`，下游无法区分该**等分片**还是该**丢弃**——
   这正是省网 unknown 率虚高的主因（坏包被计入"再等等就能识别"的桶里，
   而它永远等不出结果）。框架层 `Malformed` 优先于 `NeedMore`。

2. **只看首包、不重组**（本层是纯函数）
   省网要在连接建立后几百微秒内出结果，等流拼完整 SLA 已过。
   代价是被切开的首包判 `NeedMore` —— 由重组层补（见 2.2），**不改解析器**。

3. **GREASE 必须剔除**（RFC 8701，`0x0a0a` 等 16 个值）
   否则 JA3 对同一客户端产出不同指纹，指纹库直接失效。数值段用**十进制**
   （`0x1301` → `4865`），空段留空（`771,,,,`）。

4. **零第三方依赖**：MD5 自实现（JA3 需要）。
   不是为了洁癖 —— 是为了保持「离线可构建、工具链可验证」。

### 2.2 TCP 乱序重组（`4d62530`）

**动因**：DPI 的 `NeedMore` 需要有价值，「补字节的人」就是这一层。

新增 `src/reassembly/`，五个文件各担一件事：

| 文件 | 职责 | 关键约束 |
| --- | --- | --- |
| `seq.rs` | 32 位序号回绕算术 | 10G 链路跑满约 **3.4 秒**就绕一圈——回绕不是边界情况而是必现 |
| `intervals.rs` | 有序区间集 | 三条不变式：按 start 严格递增 / 互不相交 / 互不相邻 |
| `stream.rs` | 单向流 | 内存上限按**保连续弃乱序**降级 |
| `tcp.rs` | 头与选项解析 | TLV 长度越界即**停止**解析，不"跳过继续" |
| `tests.rs` | 向量驱动断言 | 向量 `include_bytes!` 编进二进制 |

**四个必须延续的设计决定：**

1. **重叠仲裁默认 `KeepOld`（Linux `tcp_trim_head` 语义）**
   含义是「流的内容一旦定下就不再被后续报文改写」。旁路设备要复现的是
   **接收端真实收到的字节流**，而不是攻击者最后重发的那个版本。
   代码里同时提供 `KeepNew`（BSD），因为两种语义真实存在且**行为相反**，
   必须显式选择而不是隐式固定。

2. **`anchored_by_syn` 标志必须保留**
   抓到 SYN 才锚 ISN+1；旁路中途接入时以首个数据段锚定，此时该标志为 `false`。
   用途是让下游能看见「这条流的开头完整性未知」——若抹掉这个区别，
   「开头不完整」会被静默当成「开头就是这个字节」。

3. **内存上限的降级方向是「保连续、弃乱序」**
   上限触发时，能推进连续前缀的段照收（马上会被交付并释放），
   只会加深空洞的段丢弃。这样即便在攻击流量下，DPI 依然能在流的开头拿到
   完整前缀并出结果——退化了但没瞎，比"整体停摆"有用得多。

4. **与 DPI 的衔接只有一处**：`Stream::identify_app()`
   把重组后的连续前缀喂给同一个纯函数 `dpi::identify`。
   若发现需要为重组改 DPI，说明分层串了。

### 2.3 顺带修掉的真实缺陷

| 缺陷 | 表现 | 根因 |
| --- | --- | --- |
| MD5 初值 B 写错 | 全部 JA3 指纹错误 | `0xEFCD89AB` 应为 `0xEFCDAB89`（**三个独立实现都错在同一处**，靠移植到 Python 与 `hashlib` 逐步比对才定位） |
| MD5 摘要字节序反 | 32 字符、外观合法、每两字符都反 | 应逐 u32 按小端字节输出 |
| MD5 第 3 轮 G 表抄错 | 摘要全错 | 正确为 `5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2` |
| TLS 握手长度位置错 | 得出荒谬的 `0x010000` | 是 **3 字节**且从**偏移 6** 起（不是 2 字节从偏移 5） |
| `Cursor` 起始偏移漏 9 | 每个字段都错位 | 握手体起点偏移 9 |
| 扩展体长度头被当列表元素 | JA3 里多出来路不明的小数字 | SNI / `supported_groups` 有 2 字节长度头；`supported_versions` 是 **1 字节** |
| 生成器畸形样本其实合法 | 测的是空气 | `tls-bad-inner-len` 偏移漏算 4 字节握手头，改坏的是 random |
| SACK 选项长度算成 `8n` | SACK 块解析不出 | 应为 `8n+2`（含 kind 与 len 两字节） |

---

## 3. 代码地图

```
dataplane/
  packet-engine/          C/C++17 采集与解析
    include/packet_engine/
      backends/           后端接口与 iface_list
      channel/            共享环区域（C++ 侧实现）
    src/backends/         pcap_file / af_packet / bpf_capture / iface_list
    src/channel/          region（mmap）/ producer（SPSC）
    cli/                  cythsec-parse / cythsec-capture / cythsec-ring-feed / cythsec-dump-abi
    tests/                packet / parser / pcap / channel_abi / channel_producer / live_capture
  traffic-engine/         Rust 分析
    src/channel/          共享环消费端（region / consumer / decode / abi_gen）
    src/dpi/              ★ 本批：tls / dns / http / attributes / types / md5（+ tests）
    src/reassembly/       ★ 本批：seq / intervals / stream / tcp（+ tests）
    src/flow/ session/    Flow / Session 最小模型（尚未扩展为分片流表）
    src/attributes_gen.rs 由 configs/registry/attributes.json 生成
    src/testjson.rs       测试共用最小 JSON 解析器
    src/bin/              dump_abi / ring_consume

configs/registry/         ★ 真源：attributes.json / channel-abi.json
tools/codegen/            真源 → 四语言绑定生成器
datasets/                 测试向量（pcap 与 expected.json 是生成物，不入库）
scripts/verify/           check-attributes / check-channel-abi / check-channel-parity /
                          check-dpi-vectors / check-reassembly-vectors /
                          e2e-shared-ring / e2e-control-plane

services/                 Go 控制平面（约 9000 行源码 / 7000 行测试，19 个测试包全过）
  pkg/                    共享库：attributes(生成) / controlplane / httpx / logging /
                          metrics / configutil / versioninfo
  routerd/                网卡与路由信息只读 API（netinfo: interfaces/routes/system/traffic）
  policyd/                ★ 策略引擎内核（见下），4362 行源码
  dnsd/                   DNS 策略服务（zone / load / api / config）
  telemetryd/             遥测监控（target / load / store / api / config）

web/console/              React 控制台（5 页：Dashboard / Interfaces / Routes / System / Traffic）
```

**`policyd/internal/ruleir/` 是控制平面里最厚的一块**，做前必须先读懂它的设计意图：

| 文件 | 内容 |
| --- | --- |
| `ir.go` | 规则中间表示（已归一化） |
| `compile.go` | 源规则 → IR 编译 |
| `match.go` | 条件匹配（1118 行，最厚） |
| `evaluate.go` | 判定求值引擎：**allow 优先**、条件级 Trace 可解释 |
| `store.go` / `action.go` | 内存索引与动作模型 |
| `api/rules.go` | HTTP API（含试算） |

**已做 / 未做的分界**（决定下一棒从哪里接）：引擎内核（解析、编译、匹配、求值、
API、内存存储、测试）**已做**；**落地侧全未做**——nftables 下发、原子生效与回滚、
PostgreSQL 持久化、策略版本化、命中统计、审计日志、服务间联动
（搜 `nftables` / `pgx` / `audit` 在 `services/policyd/` 下零命中，可自行复核）。

**核心体系（全仓贯穿）**：真源 JSON → codegen 四语言绑定 → verify 脚本关口。
任何一层的常量都不允许在任何语言里手写字面量。

---

## 4. 验证体系：怎么跑，每道关口拦什么

```bash
bash scripts/test/test-all.sh            # 全部（含向量自动生成）
bash scripts/test/test-all.sh --rust --dpi --reassembly   # 日常快速回路
bash scripts/lint/lint-all.sh            # 七项格式 / 真源一致性
```

| 开关 | 拦什么 | 当前结果 |
| --- | --- | --- |
| `--cpp` | C++ 单元与集成（ctest） | 6/6 通过 |
| `--rust` | Rust 全部单测 | 158 项通过 |
| `--go` | Go 控制面测试 | 通过 |
| `--node` | 前端 vitest（`npm ci` + `npm test`） | 测试 25 项通过，但 `npm ci` 被环境拦 → 见 §7.1 |
| `--parity` | 通道 ABI 跨语言取值一致性（逐行 diff） | 89 行一致（需配 `--cpp --rust`） |
| `--dpi` | **tshark 独立复核** DPI 向量 | 22 项一致（跳过 10 项已知例外） |
| `--reassembly` | **tshark 独立复核** 重组向量 | 16 项一致（跳过 2 项已知例外） |
| `--e2e` | C++ 进程写 → 共享环 → Rust 进程读并解 Flow | 4 阶段 / 19 项通过（需配 `--cpp --rust`） |

**两条用法约束**（踩过：单独选会被脚本直接拒绝并 `exit 2`）：

- `--parity` 与 `--e2e` **必须与 `--cpp --rust` 同时选** —— 它们校验的对象是
  编译出来的两端产物/进程，缺一侧就无法成立。脚本拒绝是刻意的：
  *静默跳过会让人以为验过了*。
- 前端**类型检查不在这里**，在 `lint-all.sh` 里（静态检查不依赖运行时）。
  分开的理由：`test-all.sh` 需要真实构建产物，`lint-all.sh` 只看源码文本。

**lint 七项明细**：`[cpp] clang-format` · `[rust] cargo fmt` · `[go] gofmt` ·
`[codegen] 属性字典生成物一致性` · `[codegen] 通道 ABI 双端契约一致性` ·
`[node] 前端类型检查（vue-tsc / tsc --noEmit）` · `[node] eslint`。

**`test-all.sh` 现在会先自动生成向量**（`gen_datasets`）。
理由：`datasets/**/*.pcap` 与 `*.json` 都在 `.gitignore` 里（字节级可复现，
不该占 diff），而 Rust 刻意用 `include_bytes!` 把向量**编进二进制**
（路径错 = 编译失败，而不是运行时静默什么都不测）——
所以全新克隆里缺文件是**硬失败**，必须有人补齐。

### 4.1 三方互证方法论（本项目最重要的方法论）

```
生成器（知道放了什么，自算期望值）
      ↓ 同一份 expected.json
Rust 实现（读期望值断言）
      ↕ 独立比对
tshark（第三方独立实现）
```

**为什么必须有第三方**：一致性本身证明不了正确性。只要生成器和实现犯**同一个**
理解错误（比如都把 GREASE 算进 JA3、都把握手长度当 2 字节），两边依然会完美一致。
tshark 是唯一能发现「一致地错」的手段。

**已知例外必须显式标注**，不能默认通过。目前共 3 条：

| 例外 | 原因 |
| --- | --- |
| `tls-ech-no-outer-sni` | tshark 4.6.7 的 ECH 解析器认不出手工构造的 ECH 体，会连整包 JA3 一起抑制 |
| `overlap-conflict` | 重叠仲裁策略与 tshark 不同且不可配置，两边期望值必然不同 |
| `memory-cap` | tshark 没有内存上限，会把被本实现丢弃的段也算进重组结果 |

三条都在 `expected.json` 里标 `tshark.verified=false` + 写明原因，
**并有测试守门**（`ech_vector_is_marked_as_not_tshark_verified`、
`known_exceptions_are_explicitly_marked`）防止被悄悄改回 `true`。

### 4.2 改动后必须做的反向注入验证

「检查通过」与「检查根本没跑」的输出都是绿色。因此**新增或修改门禁后**，
必须注入一个必然违规的输入确认它会报错，再恢复现场并做字节级比对。

本批三次注入的实际结果（都写进了提交信息）：

| 注入 | 结果 |
| --- | --- |
| 改坏 `expected.json` 的 sha256/len/memory_drops | ✓ 两道门禁双双报错（`exit=1`） |
| FIN 序号写成 `seq`（漏算载荷长度） | ✓ 2 项测试失败 |
| 把 `feed` 里「先数据后 FIN」对调 | ✗ **76 项测试全绿** |

第三次是**有价值的失败**：它证明了该顺序对最终状态实际无影响
（`on_fin` 只记序号，与插入互不干扰），于是把源码里那句
「顺序**必须**是先数据后 FIN」的夸大注释改成了真实约束
（真正敏感的是 FIN 的**序号**）。教训：注释里写的因果关系也要被验证。

---

## 5. 项目约定（必须延续）

1. **C++ 新增文件必须跑 `clang-format -i`**
   工具在 `/Library/Developer/CommandLineTools/usr/bin/clang-format`（**不在 PATH**）。
   历史事故：29/30 文件不合规却因检测不到工具而被静默跳过，
   本地绿灯、CI 必红。本轮又复发一次（新文件未格式化），已全仓修净。
   → **建议把 `clang-format -i` 变成保存钩子或 pre-commit**。

2. **shell 中变量引用一律用 `${VAR}` 花括号形式**
   macOS 自带 `bash 3.2.57` 会把紧跟 `$VAR` 后的多字节字符**并入变量名**，
   在 `set -u` 下直接 `unbound variable` 中断。历史 5 处事故。

3. **注释里声称「有脚本会拦下」的，该脚本必须真实存在并挂在门禁上**
   历史事故：4 处注释这么写，而那个脚本**并不存在**。

4. **真源单一**：`configs/registry/*.json` 是唯一真源。
   四语言侧只允许**引用生成物**（`attributes_gen` / `abi_gen`），
   禁止手写 `"ATTR_..."` 之类字面量。

5. **未识别 ≠ 识别为无**：SNI 为 `None` 时**不产出** `ATTR_TLS_SNI`，
   而不是产出一个空串属性。空串在下游会被当成「确实没有」，语义相反。

6. **测试向量必须编进二进制**，不许运行时读文件。运行读文件的话，
   路径写错或工作目录不对时测试会「安静地什么都测不到」——输出全绿，
   实际一条断言都没跑。这是本项目反复踩过的假绿灯。

7. **期望值手写，不许「跑一遍实现记下来」**。后者等于让被测实现给自己的
   答案打分，两边一起错的时候看不出来。

---

## 6. 已知未达成（诚实清单，不要在报告里抹平）

| 项 | 缺口 | 阻塞原因 |
| --- | --- | --- |
| `CYS-PKT-007` | macOS 真抓包未验收 | `/dev/bpf*` 属 `root:wheel 600`，本机无免密 sudo。e2e 中显式标 `SKIPPED`，**不显绿** |
| `CYS-PKT-008` | 「吞吐显著高于 pcap live」无实测对照数据 | 三发行版仅验证了**编译通过 + 真实抓包**（Ubuntu 24.04 / Rocky 9 / openEuler 24.03 容器内） |
| `CYS-TRF-019` | 「样本集准确率 ≥ 95%」无样本集 | 现有 21 条向量只证明**边界正确**，不构成准确率指标 |
| `CYS-TRF-016` | 双向 `Reassembler` / 超时 / 连接表驱逐未做 | 当前只有单向 `Stream` |
| `CYS-TRF-034` | 「真实网卡 → Flow」未达成 | 受 `CYS-PKT-007/008` 阻塞；已达成的是「真实 pcap → 环 → Flow」 |
| `CYS-TRF-001` | 未拆 cargo workspace | **刻意延后**，见 §2 顺序决策；模块边界已按 crate 语义划分好，将来是纯目录搬移 |
| — | HTTP 的 UA/状态码/Content-Type/Length 与响应侧未做 | 仅请求行三元组 + Host |
| — | DNS 的 RCODE/EDNS0 与 ANSWER 解析未做 | 仅 QNAME/QTYPE |
| — | `VERSION=9.9.9` 与 `Cargo.toml`/`package.json` 的 `0.1.0` 不一致 | `scripts/release/check-version.sh` **当前会失败**，发版前必须定哪个是真值 |
| policyd 落地侧 | nftables 下发 / 原子生效与回滚 / PostgreSQL 持久化 / 策略版本化 / 命中统计 / 审计日志 / 服务间联动 **全部未做** | 引擎内核已就绪（§3），缺口在「把判定结果落到内核与库」这一段 |
| `dnsd` / `telemetryd` | 领域模型与 API 在，但与 policyd 的策略模型未统一、无真实后端 | 见 BACKLOG `CYS-DNS-014` / `CYS-TEL-010` 一类联动任务 |
| **待办表本身** | `BACKLOG.md` 的控制平面部分滞后于代码（见 §1 顶部提醒） | `8e0fb03` 等并行提交未回写状态；刷新时需**逐项对代码核实**，不要凭印象批量打勾 |

---

## 7. 本机环境坑（踩过的，别再踩）

1. **批量删除保护会拦 `npm ci`，且报错信息误导**
   环境有 `safe-delete` 钩子：单轮删除 ≥50 个目标时拒绝并报
   `SAFE_DELETE_BULK_CONFIRM_REQUIRED`。`test-all.sh --node` 里的 `npm ci`
   要清掉整个 `node_modules/.bin`，实测 **7884 个目标**——必然中招，
   于是脚本打印 `✗ [node] npm ci 失败（可能需要网络）`。

   **这句话是误导**：不是网络问题，装包并不需要联网（依赖已缓存）。
   更糟的是它会让人去查网络、查 registry，而真正的原因在删除阶段。

   处置（按优先级）：
   - 只想验前端代码：`cd web/console && npm test` → 25 项通过。
   - 需要重装依赖：手动跑 `npm ci --no-audit --no-fund`（会触发沙箱升级确认，
     批准后 `added 311 packages in 22s`）。**已被拦的 `npm ci` 不会破坏现场**——
     拦截发生在删除阶段之前，`node_modules/.bin` 实测 23 个文件完好。
   - 建议的根治（留给下一棒）：把 `test_node()` 改成「`node_modules/.bin` 存在
     就直接 `npm test`，不存在才 `npm ci`」，并把被拦截的错误单独报成
     「环境拦截，未执行」而不是「失败」。

   > 历史记录：早先 e2e 也曾在全量跑时报红，曾被一并归入此项。**2026-10-02 复测
   > 已不成立**：`bash scripts/test/test-all.sh --cpp --rust --e2e` →
   > `测试汇总：全部通过 ✓`。所以本机现在**只有 `--node` 一项会红**。

2. **`rm -rf` 与批量操作优先走回收站**，且逐批确认。

3. **`sed -i ''` 在 macOS 上易被误当成文件名**。改文件用编辑工具逐处改。

4. **三发行版容器验证必须在同一次 `docker run` 内完成安装与编译**，
   否则容器退出即丢失（apt/dnf 装的依赖随容器消失）。

5. **`datasets/` 下的 pcap 与 json 是生成物**（`.gitignore` 覆盖）。
   改动向量定义后要重新跑生成器，并把 `expected.json` 的变化与实现改动一起提交。

---

## 8. 下一棒建议顺序（含理由，可据实际情况调整）

### 第一梯队：把已落地的东西收口（低风险、高收益）

| 顺序 | 任务 | 理由 |
| --- | --- | --- |
| 1 | `CYS-PKT-007/008` 收尾：`e2e-live-capture.sh` + 吞吐对照实测 | 唯一阻塞 `CYS-TRF-034` 验收的项；吞吐数据是省网需求的核心论据 |
| 2 | 修 `VERSION` 不一致 | 发版路径现在就是红的，越晚改越痛 |
| 3 | `CYS-TRF-020/023` 补全（HTTP 响应侧与 UA、DNS RCODE/EDNS0） | 已落地部分的自然延伸，向量体系现成，加样本成本低 |
| 4 | 修 `test_node()` 的 `npm ci` 拦截（见 §7.1） | 每一项全量门禁都会撞一次这个假红灯，且报错信息指向"网络"这个错方向。改动约十行，收益是「全量跑真的能全绿」 |

> 建议把 `clang-format` 与 `cargo fmt` 装成 pre-commit 钩子。本批已是第二次
> 因忘记格式化导致 lint 成片报红。

### 第二梯队：分析闭环（依赖已就绪）

按 BACKLOG 第 4 批的意图，当前最该补的是**从「能识别」走到「能产出记录」**：

| 顺序 | 任务 | 理由 |
| --- | --- | --- |
| 5 | `CYS-TRF-005` 规范化五元组 | 极小的改动（P0/S），但双向包能否正确归属同一个会话键，是整个会话模型的地基 |
| 6 | `CYS-TRF-006/007/008` 分片流表 + 超时老化 + 逐出 | 现在 `flow` 是「最小模型」，没有容量上限与超时，无法承载真实流量 |
| 7 | `CYS-TRF-012` TCP 状态机完整版 | 替换现有「双向有包即 Established」启发式。**注意**：重组层已提供 FIN/RST 语义与 SYN 锚定，状态机应当复用而不是另写一套 |
| 8 | `CYS-TRF-027/033` 特征提取 + FlowRecord schema | 产出可存储的记录，「分析闭环」的终点 |
| 9 | `CYS-TRF-035` 离线 pcap 处理 CLI | 让上面这些能在 `datasets/pcap/` 上批量跑，是最容易做的端到端验证 |

### 第三梯队：结构化重构（有明确前置时才做）

- `CYS-TRF-001` 拆 workspace：现在做是**纯目录搬移**。建议在第二梯队
  （尤其是流表与特征）落地后再做 —— 那时才会真正出现跨 crate 的依赖，
  提前拆只会让裁决语义长期无法统一。
- `CYS-TRF-016` 双向 `Reassembler` + 超时驱逐：需要会话层先有流表。

### 并行线：控制平面（Go，与上面那条线互不阻塞）

这条线由**另一个协作者**推进（实现全部来自 `9748175` / `8e0fb03`）。若由你接手：

| 顺序 | 任务 | 理由 |
| --- | --- | --- |
| C1 | **先读 `policyd/internal/ruleir/`，再决定做什么** | 引擎已完整（约 3700 行源码 + 2896 行测试）。先读能避免重写；`evaluate.go` 里写明了「allow 优先」是**可用性理由**而非偏好，不要改回去 |
| C2 | 刷新 `BACKLOG.md` 的控制平面部分 | 现表与代码差得最多的一段。刷新时逐项对代码核实（`go test ./...` + 搜包名），别批量打勾 |
| C3 | `CYS-POL-007` nftables 下发 | 引擎唯一缺的「出口」：IR 目前只能判定，不能生效。这是把 policyd 从「可试算」变成「可管控」的分界 |
| C4 | `CYS-POL-008` 原子生效与回滚 | 必须在 007 之后：没有快照就谈不上回滚，而防火墙类设备最怕半生效 |
| C5 | `CYS-POL-005` 的 PG 持久化 + 版本化/审计 | 现存储是纯内存（`store.go`），重启即丢；审计是合规硬需求 |

> **平台注意**：nftables 只在 Linux 生效，本机是 macOS。验证要在
> Parallels 的 Kali VM 或容器里做，且容器内安装+测试必须放在**同一次** `docker run`
> 中（见 §7.4）。

### 可选增强（P2/P3）

- `CYS-TRF-022` TLS 证书解析（明文可见部分）
- `CYS-TRF-026` `cargo-fuzz` 对 HTTP/TLS/DNS 解析器做模糊测试 ——
  解析器已在处理**敌意输入**（省网必然遇到畸形包），这是当前最值得补的一道防守
- `CYS-TRF-024` QUIC（需密钥派生，XL）
- `CYS-TRF-018` IP 分片重组（与 TCP 重组同源，可复用 `intervals.rs`）

---

## 9. 交接检查清单

接手后按此顺序确认环境可用（约 2 分钟）：

```bash
# 1. 工作区干净、状态点正确
git log --oneline -3                      # 期望看到 4d62530 / fb031ef
git status --short                        # 期望为空

# 2. 关键门禁全绿（会自动生成测试向量）
bash scripts/test/test-all.sh --rust --dpi --reassembly
#    期望：Rust 158 项通过 + 两道 tshark 核验（22 / 16 项）通过 + 测试汇总全部通过

# 3. 格式与真源一致性（前端类型检查也在这里）
bash scripts/lint/lint-all.sh             # 期望：七项全过（含 node 类型检查与 eslint）

# 4. 端到端 + ABI parity（两者都必须带上 --cpp --rust）
bash scripts/test/test-all.sh --cpp --rust --parity --e2e
#    期望：parity 89 行一致 + e2e 4 阶段 / 19 项断言 + 测试汇总全部通过

# 5. 前端单测（不要用 --node，它会先跑 npm ci 并被环境拦）
(cd web/console && npm test)              # 期望：4 文件 / 25 项通过

# 6. 待办表状态
bash docs/planning/scripts/count-backlog.sh | tail -20
/Users/xuzhongxin/.workbuddy/binaries/python/versions/3.13.12/bin/python3 \
  docs/planning/scripts/check-deps.py
#    期望：无环、无悬空、无自依赖；2 处状态不一致为既有已记录项（CYS-PKT-006/024）
```

**若看到 `✗ [node] npm ci 失败（可能需要网络）`**：那是 §7.1 的环境拦截，
不是网络问题也不是代码缺陷——照上面第 5 步单独跑 `npm test` 即可。

**环境依赖**：`cmake` / `cargo` / `go` / `node` / `npm` / `python3` / `tshark`（4.6.7）。
缺 `tshark` 时两道核验会明确打印「未核验…不计为通过」并返回 0 ——
**这是刻意的**：装不装 tshark 是环境问题，但绝不能把它显示成"通过"。

---

## 10. 一句话交给下一棒

**当前最缺的不是更多协议解析器，而是「从报文到可存储记录」的那一段**：
流表、超时、状态机、特征、FlowRecord。
解析能力（DPI）与重排能力（reassembly）已经扎稳并有第三方互证，
但它们目前只输出「识别结论」，还没有一条路径把它们变成能落库、能查询的流量记录。
第二梯队就是从「能识别」走到「能产出记录」的那条路。

**另请留意**：`tshark` 交叉核验是这套代码唯一的"外部真相来源"。
新增任何协议解析器时，如果找不到第三方参照，宁可显式标注
`verified=false` + 原因，也不要让它默认通过 ——
**「未被核验」冒充「已核验通过」是本项目最需要防的事**。
