# CythSec 项目长期记忆

> 最近更新：2026-10-02（状态点 `d322171`）
> 接力文档：`docs/planning/HANDOFF.md` ｜ 主待办表：`docs/planning/BACKLOG.md`

## 核心体系（不可违反）

真源 JSON（`configs/registry/attributes.json`、`channel-abi.json`）→ `tools/codegen/gen-*.py`
四语言绑定 → `scripts/verify/*.sh` 关口。**任何语言侧禁止手写常量字面量**，只引用生成物
（`attributes_gen` / `abi_gen`）。

## 门禁与跑法

- `bash scripts/test/test-all.sh`（全部，会先自动生成测试向量）
- 日常快速回路：`--rust --dpi --reassembly`
- `--parity` 与 `--e2e` **必须与 `--cpp --rust` 同时选**（否则脚本 `exit 2` 拒绝）
- `bash scripts/lint/lint-all.sh`（7 项：cpp / rust / go / codegen×2 / node 类型检查 / node eslint）
- ⚠ `--node` 在本机**必红**：`npm ci` 被环境 safe-delete 钩子拦（7884 目标 > 阈值 50），
  报错文案误指「网络」。规避：`cd web/console && npm test`（25 项）

## 项目约定（长期）

1. C++ 新增文件必须跑 `clang-format -i`（工具在 `/Library/Developer/CommandLineTools/usr/bin/clang-format`，**不在 PATH**）
2. shell 中变量引用一律 `${VAR}`（macOS bash 3.2 会把紧跟的多字节字符并入变量名）
3. 注释里声称「有脚本会拦下」的，该脚本必须真实存在并挂在门禁上
4. **未识别 ≠ 识别为无**：`None` 时不产出属性，而非产出空串属性
5. 测试向量编进二进制（`include_bytes!`）；期望值**手写**，不许「跑一遍实现记下来」
6. 新增/修改门禁后必须做**反向注入验证**（绿色的「通过」与绿色的「没跑」长得一样）
7. **状态标记与实现同批提交**；刷新滞后状态时逐项核对验收标准，不凭印象批量打勾
8. **文档里的数字与结论当场复跑**；沿用的旧结论必须重新验证

## 测试环境

- **Linux 侧测试机**：macOS（VMware Fusion）上的 Rocky Linux 10.2 aarch64 虚拟机（主机名 `hkcfw`），
  用于真实抓包 / 真实网卡验证（`CYS-PKT-007` / `CYS-PKT-008` / `CYS-TRF-034`）与 aarch64 64 KiB 页路径。
  凭据不入本仓库；登录信息与网络拓扑见本地知识库：
  `/Users/xuzhongxin/Documents/智能体长期神经网络/SuperAGIRAS/50-Environment/VMware-Rocky-TestVM.md`

## 已知偏差（不要在报告里抹平）

- `BACKLOG.md` §3.4 M4 控制平面状态**滞后于代码**（`policyd` / `dnsd` / `telemetryd` / `pkg`
  已存在且 19 个 Go 测试包全过，真实缺口在**落地侧**：nftables / 原子回滚 / PG / 版本化 /
  审计 / 联动）—— 详见 `HANDOFF.md` §1
- ~~`VERSION=9.9.9` 与 `Cargo.toml` / `package.json` 的 `0.1.0` 不一致~~ **已修（2026-10-04）**：真源定为
  `0.1.0`，四端（C++ `configure_file` / Rust `build.rs` / Go `-ldflags -X` / 前端 `vite define`）全部派生，
  产物级实测通过（`scripts/release/check-version-bump.sh`）。**两个连带发现**：① 检查器此前没有任何门禁
  调用（已挂 `lint-all.sh` 第 6 条 + `--self-test` 反向注入）；② 它所在目录被 `.gitignore` 的裸
  `release/` 规则整个忽略、**从未入库**（已改 `/release/` 并把两份脚本入库）—— 详见 `HANDOFF.md` §5/§7
