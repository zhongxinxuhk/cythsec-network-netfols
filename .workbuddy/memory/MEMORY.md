# CythSec 项目长期记忆

> 最近更新：2026-10-05（状态点 `2ca80b6` 之后：离线流水线已接线 `--workers N`）
> 接力文档：`docs/planning/HANDOFF.md` ｜ 主待办表：`docs/planning/BACKLOG.md`

## 核心体系（不可违反）

真源 JSON（`configs/registry/attributes.json`、`channel-abi.json`）→ `tools/codegen/gen-*.py`
四语言绑定 → `scripts/verify/*.sh` 关口。**任何语言侧禁止手写常量字面量**，只引用生成物
（`attributes_gen` / `abi_gen`）。

## 门禁与跑法

- `bash scripts/test/test-all.sh`（全部，会先自动生成测试向量）
- 日常快速回路：`--rust --dpi --reassembly`
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

## 测试环境

- **Linux 侧测试机**：macOS（VMware Fusion）上的 Rocky Linux 10.2 aarch64 虚拟机（主机名 `hkcfw`），
  用于真实抓包 / 真实网卡验证（`CYS-PKT-007` / `CYS-PKT-008` / `CYS-TRF-034`）与跨架构（aarch64 / 4 KiB 页）路径。
  **凭据不入本仓库**；主机名、两地址、Fusion 路径、忘记密码时的 GRUB 重置法与 IP 失联时的租约查法，
  见本地知识库：`/Users/xuzhongxin/Documents/智能体长期神经网络/SuperAGIRAS/50-Environment/VMware-Rocky-TestVM.md`
- **接入方式（2026-10-05 建立，推荐）**：专用密钥已装好，免密且口令不进脚本/命令行/仓库：
  - `ssh cythsec-dev` → NAT `172.16.191.129`（用户给的地址）
  - `ssh cythsec-dev-ho` → Host-Only `172.16.135.128`（抖动更小，**大文件传输优先用它**）
  - 私钥 `~/.ssh/id_ed25519_cythsec_dev`（**只在本机**；别名写在 `~/.ssh/config`）
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
  `--live` **13/13 真实网卡断言**（`enp2s0`，74 包 / tshark 74 帧 / 环 74=74 / 10 条 Flow；该关口加了裁判口径自证后为 14 项）。
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
  额度，一旦发生逐出，输出与 `--workers 1` 不再逐字节一致（CLI 每次打印 `evicted=`）

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
