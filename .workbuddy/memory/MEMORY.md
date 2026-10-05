# CythSec 项目长期记忆

> 最近更新：2026-10-05 第十一段（**流级采样落地**：`--sample 1:N` 真丢包 + IE 34 与执行**同源**；顺手抓出 `ExportConfig.sampling_interval` 被硬编码忽略 —— 「配置项看起来在做事、实际什么也没做」）
> 接力文档：`docs/planning/HANDOFF.md` ｜ 主待办表：`docs/planning/BACKLOG.md`

## 核心体系（不可违反）

真源 JSON（`configs/registry/attributes.json`、`channel-abi.json`）→ `tools/codegen/gen-*.py`
四语言绑定 → `scripts/verify/*.sh` 关口。**任何语言侧禁止手写常量字面量**，只引用生成物
（`attributes_gen` / `abi_gen`）。

## 门禁与跑法

- `bash scripts/test/test-all.sh`（全部，会先自动生成测试向量）
- 日常快速回路：`--rust --dpi --reassembly --flows --ipfix`
- `--ipfix`（2026-10-05 新增）：IPFIX 导出的第三方交叉核验 —— tshark 解 `--ipfix-pcap` 产物，
  九类字段与 JSONL 逐条比对 + 报文级不变量（version / length vs UDP 载荷 / 序列号累计 /
  模板可见性 / 刷新间隔）+ IE 152/153 用 **PDML 原始 8 字节**比对 + 本机 UDP 通道字节与
  pcap 载荷逐字节比对 + 5 项产物级反向注入（改计数值 / 改 setID / 改报文长度 / 截断 /
  改时标）。**流级口粮**：`--ipfix-udp`/`--ipfix-pcap`/
  `--ipfix-domain`/`--ipfix-max-msg`/`--ipfix-template-refresh`
- `--parity` 与 `--e2e` **必须与 `--cpp --rust` 同时选**（否则脚本 `exit 2` 拒绝）
- `bash scripts/lint/lint-all.sh`（9 项：cpp / rust / go / codegen×2 / version（含自证）/ repo / node 类型检查 / node eslint）
- **测量脚本（不是门禁，不会自动跑）**：`bash scripts/verify/bench-pipeline.sh [包数] [轮数]`
  —— 量「整条离线流水线加 worker 有没有用、上限在哪」（先 `cargo build --release --offline`）。
  绝对吞吐机器相关，**刻意不做阈值判定**；它的正确性部分由 `--rust` 里的单测常驻把关
  （1/2/3/4/8 个 worker 输出逐字节一致、分片均衡度、两方向同分片）
- `--node`：`node_modules` 已在位时脚本会**自动跳过 `npm ci`**（不会误红）；若强制走 `npm ci`
  （`CYTHSEC_FORCE_NPM_CI=1`）而被环境 safe-delete 钩子拦（7884 目标 > 阈值 50），脚本按
  `ENV_INTERCEPTED` 单独分类并明说"不是网络问题"，不再把环境限制报成代码失败
  （`--self-test` 用 stub npm 自证这条分类；2026-10-05 实测 `--node` 通过）

## 项目约定（长期）

1. C++ 新增文件必须跑 `clang-format -i`（工具在 `/Library/Developer/CommandLineTools/usr/bin/clang-format`，**不在 PATH**）
2. shell 中变量引用一律 `${VAR}`（macOS bash 3.2 会把紧跟的多字节字符并入变量名）
3. 注释里声称「有脚本会拦下」的，该脚本必须真实存在并挂在门禁上
4. **未识别 ≠ 识别为无**：`None` 时不产出属性，而非产出空串属性
5. 测试向量编进二进制（`include_bytes!`）；期望值**手写**，不许「跑一遍实现记下来」
6. 新增/修改门禁后必须做**反向注入验证**（绿色的「通过」与绿色的「没跑」长得一样）
7. **状态标记与实现同批提交**；刷新滞后状态时逐项核对验收标准，不凭印象批量打勾
8. **文档里的数字与结论当场复跑**；沿用的旧结论必须重新验证
9. **把结构化键映射到 N 个桶（分片/分区/负载均衡）时，必须"先雪崩混合再取模"** ——
   FNV-1a 的**低位只由最后几个字节决定**，而流键尾部（目的端口、协议号）在同一批流量里
   完全相同 → `fnv(...) % workers` 的低位恒定，全部流挤到少数 worker 上，
   **输出完全正确、单测全绿、并行度为零**。测均衡要用**真实流量的字节布局**
   （变化在前部）并断言均衡度**上下界**，只断言"每个分片都用到过"会漏掉它（2026-10-05 实测踩到）

## 采集侧（AF_PACKET / BPF）关键事实（2026-10-05 实测确立）

- **对照轴必须是「mmap 环 vs 拷贝模式」，不是「vs pcap live」**：libpcap 1.10 的 live 路径
  自己就走 `TPACKET_V3` + `PACKET_MMAP`，实测三条路径同级（每包 CPU 0.10~0.13 µs）。
  真正的差距：零丢包同负载下 mmap 环每包 CPU **5.9~6.3× 更省**（两次独立复跑）；饱和时同机端到端速率 **1.35×**；
  真实网卡上拷贝档把整机容量砍到 **1.74×** 之一（165,924 vs 95,450 pps）。
- **`PACKET_STATISTICS` 是读即清零**：`stats()` 必须现场轮询并**累加**（`+=`），
  只在 `close()` 读一次会让长跑期间的丢包不可见、被信号杀掉就永远丢。macOS BPF 的
  `stats()`（`BIOCGSTATS.bs_drop`）本来就是现场读 —— 两边语义现已对齐。
- **三类丢包要分开记账**：socket 丢（`tp_drops`）、设备丢（`rx_dropped`）、
  softnet backlog 丢（`/proc/net/softnet_stat` 第 2 列）。只看 `tp_drops` 会把「丢在别处」
  读成「零丢包」（实测拷贝臂少抓 40% 却报 0）。
- **`SO_RCVBUF` 会被 `net.core.rmem_max` 静默削顶**（Rocky 10.2 默认 212992 → 请求 4 MiB 只给 416 KiB），
  而 `PACKET_RX_RING` 不受该限制。凡请求内核资源上限，**设置后必须 `getsockopt` 回读**并如实报出。
- **`tp_mac` / `tp_next_offset` 都相对「本帧头」**，不是相对块首；字段名以
  `<linux/if_packet.h>` 与本仓 `af_packet.cpp` 为准（`num_pkts`、`offset_to_first_pkt`）。
- 采集档位 `--capture-mode <auto|v3|v2|recvfrom>` **指定即严格**：失败报错、**绝不降级**，
  不支持的后端点名拒绝并让 CLI `exit 2` —— 否则对照实验两臂可能跑同一条路径却看不出来。
- 测量顺序会影响残差：**先起抓包臂、再起打流**（反过来打流的头 0.5 s 落在无监听窗口，
  凭空 5%「未交代」）。对照脚本：`bash scripts/bench/live-throughput-docker.sh [时长] [帧长] [速率]`。

## 流级遥测（IPFIX）关键事实（2026-10-05 实测确立）

- **逐包全量在省网是量级错误**：单条 100G 平均 500 B = 25 Mpps、最坏 64 B 帧 = 148.8 Mpps；
  骨干 10 Tbps 全量 = 2.5 Gpps ≈ 1.25 TB/s ≈ **108 PB/天**；本仓单机最强是离线派发端
  **2.33 Mpps ≈ 10G 最坏帧的 16%**。正确形态是**网元采样导出 + 采集集群**，逐包只在单点用
  （`CYS-DOC-023`）。1:1000 采样后 10 Tbps → 2.5 Mpps → 约 2~4 TB/天。
- `FlowRecord → IPFIX` 编码在 `dataplane/traffic-engine/src/export/{mod,sink}.rs`，**零第三方依赖**。
  v4 模板 256 / v6 模板 257，**模板分族按需携带**；IE 编号一律取自 IANA 注册表
  （1/2/4/7/8/11/12/27/28/34/148/152/153），**不许凭记忆写**。
- **序列号 = 本报文之前该 Observation Domain 已发送的数据记录累计数**（RFC 7011 §3.1），
  模板记录不计入 —— 采集器就是靠它算导出丢包率。填充只允许零字节且必须短于 Set 内任何记录。
- **tshark 侧字段名**：`flowId`(148) 是 `cflow.flow_id`；起止时间在
  `cflow.timedelta_tree.cflow.abstimestart/abstimeend`；单模板集的 `cflow.template_id`
  在 `Template (Id = …, Count = …)` 子节点下 → 校验脚本按**字段名递归收集**，不写死键路径。
- **核验取原始值，不取渲染串**：同一份产物，macOS tshark 4.6.9 把绝对时间渲染成
  `2023-11-14T22:13:30.016000000Z`，Rocky 4.4.2 渲染成 `Nov 15, 2023 06:13:30`（本地化）
  → 解析渲染串换机器就崩。时标一律取 `-T pdml` 的 `value=`（该 IE 的线上原始字节）。
- **v1 刻意不含**：RFC 5103 双方向（反转字段 = 企业位 + PEN 29305 + 同编号；`FlowRecord`
  只有总量计数）与 DPI `applicationName`(96)（变长）。采样未实现 → `samplingInterval` 如实写 1。
- **线路格式只定义一次**：IE/模板/常量在 `src/ipfix/mod.rs`，编码器（`export/`）与采集器
  （`ipfix/collector.rs`）都 `use` 它 —— 两侧各写一份"一起错还互相验证通过"是这类协议最坏的 bug。
- **采集器（`cythsec-ipfix-collect`）硬语义**：序列号缺口 = 导出丢包条数，**只在前进方向记账**、
  界外按乱序计且**不重置基线**（RFC 7011 §3.1/§11.6，点见过"见大序号就重置"会被注入蒙蔽）；
  首报文无基线不算丢包；模板生存期 = 观测到的重传间隔 × 3（§8.4），UDP 上模板撤回**必须忽略**；
  同模板号不同定义保留旧模板并计数（§8.1）；**未知 IE 必须按长度跳过而不是删掉**
  （删掉会让后续字段整体前移，读出来仍是"合法"数值 —— 本批实测把 octets 读成 0xAABBCC0000000000）。
- **两条路径的边界（`CYS-DOC-023` 已闭环）**：包级（逐包流水线）= **单点**（DPI/取证/10~100G 点），
  判定句「要求逐包全量留存 ≥ 1 Tbps 即量级不成立」；流级（流表 → IPFIX → 采集集群）= **省网/骨干**唯一入口，
  判定句「采样率 / 导出丢包率 / 采集覆盖率三个口径都能给出具体数字，即可算并可复算」。
  **量级算式写进脚本**（不靠文档口口相传，最容易记错一位数）：10 Tbps 逐包全量 = 108 PB/天、
  1:1000 流级 = 8.64 TB/天、倍数 12,500 = 4.1 个数量级，由自证算例 G 用手算值钉住。README 有边界表。
- **容量模型（`CYS-INF-040`，`scripts/plan/collector-capacity.py`，挂 `--plan`）**：
  `记录率上界 = 带宽 ÷ (平均包长×8) ÷ 采样率`；`台数 = ceil(记录率 ÷ (每台实测容量×余量))`；
  `TB/天 = 记录率 × 86400 × 每条落盘字节`。省网 20 Tbps / 1:1000 / 500 B ⇒ 5 Mrec/s、
  2 台、17.28 TB/天；三档分解（核心 1:1000 / 汇聚 1:500 / 接入 1:100）合计 **16 Mrec/s、7 台、55.3 TB/天**
  —— **采样率是分层的，不能用出口那一档代表全网**。**每台容量必须有实测出处**：新增
  `cythsec-bench` 用例 `ipfix-collect-decode`（生产编码器造语料、只对解码计时、断言全部交付），
  M1 Pro release 实测 4.46~4.69 Mrec/s、Rocky 2vCPU 实测 4.07 Mrec/s —— 两台只差 13%，
  但 `ceil` 把它放大成 **2 台 vs 3 台**，所以模型必须 `--from-bench` 传实测值（落盘量与机器无关）。
  **三个必带口径**：采样率（规划值，真采样待 053）、
  导出丢包率（054 已落地）、采集覆盖率（**待部署清单填**，缺省 100% 不是事实）。
  模型脚本必须自带**手算期望值**而非抄输出，并做反向注入（漏除采样率 / 丢余量 / 比特当字节）。
- **"配置项存在"不等于"配置项生效"**（2026-10-05，`CYS-TRF-053`）：`ExportConfig.sampling_interval`
  有字段、有校验（拒绝 0）、有文档，唯独**没有任何一处使用它** —— `write_record` 里硬编码 `&1u32`。
  于是"声明 1:1000 采样"在代码上根本无法表达，而读代码的人会以为它能表达。**这类缺陷的判据是
  "找出该配置的所有读取点"**：只有校验、没有读取 = 装饰品。同类前科：陈旧二进制让关口测了个
  不存在的东西。修法不只是接线，而是让**声明与执行共用同一份配置**（单一来源），再加
  "改回来就红"的单测（配置 1000 与默认 1 两个方向钉住）。
- **声明与执行之间必须没有第二个开关**（2026-10-05，同上）：采样率写进 IPFIX 的 IE 34 是一句
  对外承诺，采集侧、容量模型、丢包率全跟着它走。若"一个开关声明、另一个开关执行"，就一定有
  一天会不一致。所以没做 `--ipfix-sampling`：IE 34 只从真正做丢弃决定的那份配置来。
  同类思路：`loss_ppm` 的分子分母必须同源、`采样率` 与 `实际留存比例` 必须能对照打印。
- **凡是"规划假设"，最后都要被实测替换 —— 而且替换后宣传口径要跟着改小**（2026-10-05，`CYS-INF-041`）：
  容量表里最后一个假设是"落盘 40 B/记录（列式压缩）"。真量之后：**未压缩 JSONL 1066 B/记录**、
  **gzip 79.4 B/记录**（真实语料 37 条）/ **21.0 B**（同质压测语料 20,182 条）—— 旧假设低估 2~27×。
  规划值取**两档中较差的一端**（不是平均、不是最小；这条规则写进脚本且注入 `pick-best` 必红），
  因为 gzip 档完全由"内容重复度"决定，用压测语料那个漂亮数当规划值＝把乐观假设偷偷放回来。
  连带影响：20 Tbps×1:1000 落盘 17.28 → **34.29 TB/天**、三档合计 55.3 → **109.73 TB/天**、
  逐包全量/流级倍数 12,500（4.1 个数量级）→ **6,297（3.8 个数量级）**。**假设换成实测，
  结论能不变；只要结论要变，就必须改**（否则就是把实测当装饰品）。
  两个"只有真量才会暴露"的细节：① `gzip -9 <file>` 会把文件名/时间戳写进头，`gzip -9 -c < file`
  不会（同一份 37,306 B 语料差 20 B）——不是误差，是两种方法；② 压缩档必须过**往返校验**
  （解压 == 原文）才算数，截断输入也能给出更小的数。
- **"编码器与解码器共用一份定义"是结构性盲区**（2026-10-05，`check-ipfix-interop.sh`）：
  共用一份定义是对的（避免两边各写一份、一起错还互相验证通过），但它意味着
  "我们的导出 → 我们的采集"**永远证明不了那份定义读对了 RFC**；tshark 只挡"字节不合法"。
  做法：再引入一个**独立实现**（只读 RFC 写，不 import/不复制仓库常量），并让它在每个
  "约定俗成"处**故意不同**（模板 ID、字段序、长度、观测域），否则它会不自觉地复制同一个误解。
  这次一上线就抓到：① CLI 统计行漏印 6 个联调字段（模板冲突/撤回被忽略/未登记填充…）；
  ② IE 6（tcpControlBits）IANA 有登记、真实导出器都发，而我们的 `Ie` 枚举没有它
  （当前按长度跳过、值丢弃 —— 是能力边界不是解析错）。
  另一个副产品：**"模板缺失"会让 loss_ppm 变成上界**（模板未知 ⇒ 那个 data set 有几条记录
  不可知 ⇒ 下一报文的序号差被记成 lost_records）。这是 §11.6 要求的严格读法，
  本仓选择保留严格口径 + 一起打出 `no_template_sets`，并用互操作关口把两个数钉死
  （`no_template_sets=1` ⇒ `lost_records=2` / `loss_ppm=285714`）。
- **判据里不许藏依赖现场流量的隐藏变量**（2026-10-05 两次踩到，都在 `--live` 的 D 项）：
  ① `eth.type` 对 802.3/LLC 帧给空 → 裁判少数；② 只数"非 IP"漏掉**非首片分片**
  （tshark 仍写 `eth:ethertype:ip`，我们按设计拒绝）。修法 = 把"按设计拒绝"的类别逐条枚举进
  裁判口径 + 用**合成语料跑完整判定链**做确定性自证。**"两个数相等"不能单独当自证**：
  夹具写错会"两边一起瞎"照样通过，至少要有一个数来自与被测对象无关的独立期望值。
- **`loss_ppm` 是"导出丢包率"**，含网络丢包 + 采集侧丢弃 + 导出侧自己丢的记录；
  且本版**无法设置 `SO_RCVBUF`**（std 无接口、不引第三方依赖）→ 只在小突发下口径干净。

## 测试环境

- **Linux 侧测试机**：macOS（VMware Fusion）上的 Rocky Linux 10.2 aarch64 虚拟机（主机名 `hkcfw`），
  用于真实抓包 / 真实网卡验证（`CYS-PKT-007` / `CYS-PKT-008` / `CYS-TRF-034`）与跨架构（aarch64 / 4 KiB 页）路径。
  **凭据不入本仓库**；主机名、两地址、Fusion 路径、忘记密码时的 GRUB 重置法与 IP 失联时的租约查法，
  见本地知识库：`/Users/xuzhongxin/Documents/智能体长期神经网络/SuperAGIRAS/50-Environment/VMware-Rocky-TestVM.md`
- **接入方式（2026-10-05 建立，推荐）**：专用密钥已装好，免密且口令不进脚本/命令行/仓库：
  - `ssh cythsec-dev` → NAT `172.16.191.129`（用户给的地址）
  - `ssh cythsec-dev-ho` → Host-Only `172.16.135.128`（抖动更小，**大文件传输优先用它**）
  - 私钥 `~/.ssh/id_ed25519_cythsec_dev`（**只在本机**；别名写在 `~/.ssh/config`）
  - **`ssh <host> '命令'` 是非交互 shell，PATH 里没有 `~/.cargo/bin`** → 直接跑门禁会报
    `✗ 工具链缺失: cargo`（交互登录却正常）。一律写成
    `ssh cythsec-dev-ho 'export PATH="$HOME/.cargo/bin:$PATH"; cd /root/CythSec && …'`。
    预检没有错（非交互环境里确实没有 cargo），要改的是调用姿势
- **规格与能力边界（决定在这台机上跑什么之前先看这条）**：**2 vCPU / 3 GB 内存 / 45 GB 磁盘 / 无 NUMA**。
  已装（2026-10-05 补齐后）：`rustup 1.97.1`（与本机**逐位同版本**，含 rustfmt）+ `gcc`/`g++ 14.3.1` + `cmake 3.31.8`
  + `git 2.52` + `tshark 4.4.2` + `golang` + `nodejs`/`npm` + `python3.12` —— 即**全套门禁依赖已齐**，
  `bash scripts/test/test-all.sh`（默认全量）在该机 **EXIT=0 全过**。
  **适合**：跨架构（aarch64）+ 跨发行版的**语义/正确性**验证、真实网卡（AF_PACKET）抓包、
  与 macOS（16 KiB）不同的**页大小**路径、小规模基准。**不适合**：吞吐类结论 —— 2 核上 4/8 线程档
  必然超订；且 `cythsec-bench` 的**回归下限是按 M1 Pro 标定的机器相对阈值**（`--bench` 本就默认不在
  ALL 里），在这台机上只能 `--report-only` 取数，**不得据其判红**（否则等于把"机器小"报成"代码坏"）。
  **页大小更正（2026-10-05 实测）**：该机 `CONFIG_ARM64_4K_PAGES=y` → **4 KiB 页**，**不是 64 KiB**
  （早前记的"64 KiB 页路径"有误）。它对 `af_packet.h` 的 PAGE_SIZE 运行时假设仍有价值（提供了一个与
  macOS 16 KiB 不同的页大小），但 **64 KiB 页路径至今没有覆盖环境**。
  **2026-10-05 首轮验收结果**：`--rust` **337 项全过**（与本机计数一致）、`--cpp` 6/6、
  `--live` **14/14 真实网卡断言**（`enp2s0`，74 包 / tshark 74 帧 / 环 74=74 / 10 条 Flow；该关口加了裁判口径自证后为 14 项）。
  同一批还修掉 3 处"把本机/平台假设当普遍事实"的假红（预检不分组、串行档效率断言、
  C++ 测试里的 `0xFFFF`/超长接口名常量）—— 详见 `docs/planning/HANDOFF.md` §2.7 与 BACKLOG 变更记录。
- **干净克隆里直接 `cargo test` 会失败**（2026-10-05 在虚拟机上撞到）：`datasets/**/*.pcap|json`
  被 `.gitignore` 忽略（生成物），而测试用 `include_bytes!/include_str!` 引用它们 →
  必须走 `bash scripts/test/test-all.sh --rust`（会先生成向量）。另：`test-all.sh` 的工具链预检
  现已**按所选分组**要求（此前 `--rust` 也会因缺 cmake/go 被挡住，2026-10-05 修 + 自证）。
- **代码同步姿势（2026-10-05，三个踩过的坑）**：用 `git archive`，**不要**用 `tar --exclude` ——
  macOS 的 bsdtar `--exclude=./target` 会匹配**任意层级**同名目录，实测静默丢掉
  `scripts/build/build-all.sh` 与 `services/telemetryd/internal/target/`（正是"本机全绿≠克隆能构建"那一类，
  靠目标机 `git status` 才发现）：

  ```bash
  git archive --format=tar HEAD | ssh cythsec-dev-ho 'mkdir -p /root/CythSec && tar -xf - -C /root/CythSec --no-same-owner'
  COPYFILE_DISABLE=1 tar -cf - .git | ssh cythsec-dev-ho 'tar -xf - -C /root/CythSec --no-same-owner'
  ssh cythsec-dev-ho 'cd /root/CythSec && git status --short | wc -l'   # 必须为 0 行 = 传输无损的自证
  ```

  ① 以 root 解包会保留 macOS uid 501 → git 报"可疑的所有权"，需 `chown -R root:root`（或 `safe.directory`）；
  ② 不加 `COPYFILE_DISABLE=1` 会带进 `._*` AppleDouble，`.git/objects/pack/._*.idx` 会让 git 报
  "index file is too small"；③ bsdtar 的 xattr 警告是噪声（加 `--no-xattrs` 或 `2>/dev/null`），不是失败。

## 已知偏差（不要在报告里抹平）

- **整条离线流水线的并行上限是"派发端"，不是流表**（2026-10-05 实测）：`cythsec-analyze
  --workers N` 单核 0.918 Mpps，2/4/8/16 worker 加速 1.49×/2.47×/**2.53×（上限）**/2.49×，
  平台值 0.393 s 就是派发端（读盘+解帧+分片+入队）→ **2.33 Mpps ≈ 10G 最坏帧（64B/14.88 Mpps）
  的 16%，且加核解决不了**。要线性必须让"读包+解帧"也分掉（每队列一环 = `CYS-PKT-009`）。
  在线路径 `ring-consume` **仍是单表单线程**；分片模式下每个 worker 各持 `--max-sessions`
  额度，一旦发生逐出，输出与 `--workers 1` 不再逐字节一致（CLI 每次打印 `evicted=`）。
  **跨机**：Linux 2 vCPU 测试机上同一脚本单核 0.883 Mpps（与 M1 Pro 0.918 持平），
  但 2/4 worker 只有 **1.00×/1.11×** —— 核少时派发端把收益全吃掉；脚本的 `D=最优档位`
  归因**要求 worker 数 ≥ 核数**，否则会把线程争抢误算成派发端

- `BACKLOG.md` §3.4 M4 控制平面状态**滞后于代码**（`policyd` / `dnsd` / `telemetryd` / `pkg`
  已存在且 19 个 Go 测试包全过，真实缺口在**落地侧**：nftables / 原子回滚 / PG / 版本化 /
  审计 / 联动）—— 详见 `HANDOFF.md` §1
- ~~`VERSION=9.9.9` 与 `Cargo.toml` / `package.json` 的 `0.1.0` 不一致~~ **已修（2026-10-04）**：真源定为
  `0.1.0`，四端（C++ `configure_file` / Rust `build.rs` / Go `-ldflags -X` / 前端 `vite define`）全部派生，
  产物级实测通过（`scripts/release/check-version-bump.sh`）。**两个连带发现**：① 检查器此前没有任何门禁
  调用（已挂 `lint-all.sh` 第 6 条 + `--self-test` 反向注入）；② 它所在目录被 `.gitignore` 的裸
  `release/` 规则整个忽略、**从未入库**（已改 `/release/` 并把两份脚本入库）—— 详见 `HANDOFF.md` §5/§7。
  **同一条规则家族还吞掉两处**：`scripts/build/build-all.sh`（四端构建入口）与
  `services/telemetryd/internal/target/`（telemetryd 直接 import 的 Go 包，缺了它克隆里编译不过）。
  规则已全部锚定到根，并新增门禁 `scripts/verify/check-ignored-sources.sh`（lint `[repo]`）守这一类。
  **教训：本地全绿 ≠ 克隆能构建** —— 这三处都只有真的 clone 一次才会暴露。
- **`core.autocrlf=input` 会改掉入库二进制向量的行尾（已修，2026-10-04）**：`git add` 把
  HTTP 向量载荷里的 `\r\n` 归一成 `\n`（`http.rs` 用 `\r\n\r\n` 判头部结束），实测索引 blob
  的 CRLF 计数 0 / 磁盘 5 —— 文件**在**版本控制里，但入库那份 ≠ 测试读的那份。修法：新增
  `.gitattributes` 声明 `datasets/**/*.bin -text` + `git add --renormalize`。**两个反直觉点**：
  ① `git diff` 看不见这种损坏（它比「过了 clean 过滤之后」的内容，而归一恰恰发生在过滤这一步），
  必须比 `git ls-files -s` 的 blob 哈希与 `git hash-object --no-filters`；② `.gitattributes` 会
  **缓存在索引里**（删掉文件后 `git check-attr` 仍报 `text: unset`，实验会得出假结论，须先重写索引）。
  守门：`scripts/verify/check-dpi-vectors.sh`（自证 + 逐文件比对 32 个向量，挂 `--dpi`）。
