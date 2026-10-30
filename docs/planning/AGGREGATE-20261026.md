# 2026-10-26 承载协议聚合观测增量

分支：`feat/aggregate-observability`；起点 `77a3a29`；开发期间用户追加 `.codex` 配置提交 `2f21335`，保留在本分支历史。新增独立离线入口 `cythsec-observe` 和 `observability` 模块，不调用既有应用／VPN 分类器，不输出逐用户记录、域名、载荷或 VPN 专属指纹，不执行主动探测、转发或阻断。

## 交付范围

- TCP／UDP／其他 IP 计数；TLS 记录头／QUIC v1/v2 长头候选计数。
- 窗口内随机密钥的双向整流采样、有界状态和最少 20 流输出抑制。
- TCP 序号重传／乱序／前向缺口候选、环绕／半空间歧义和元组复用处理。
- SYN 至反向 SYN-ACK 的观测时差直方图；排除重发和歧义，每个元组每窗最多贡献一次。
- 记录／字节守恒、截断、解码、时间回退、迟到、容量拒绝和来源计数状态。
- 独立 Python 合成 PCAP、CLI 反向验证、tshark 对照，默认门禁和 Rust CI 接线。

完整算法、Mermaid 数据路径、字段口径和使用命令见 [聚合观测契约](../observability/aggregate-stats.md)。

## 验证记录

以下为本轮最终实现的本地实跑结果；Rust 1.97.1、cargo 1.97.1、tshark 4.6.9。没有使用历史 BPF 审批替代本轮审批。

| 检查 | 实际退出码 | 结果 |
| --- | --- | --- |
| `PATH=/tmp/cythsec-format-env/bin:$PATH bash scripts/lint/lint-all.sh` | 0 | 完整静态门禁通过 |
| `bash scripts/build/build-all.sh` | 0 | C++／Rust Release／Go／前端构建通过；分片修正后复跑 |
| `CYTHSEC_LIVE_SUDO=1 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 0 | 完整入口执行完毕；包含下列既有例外，不能描述为所有裁判项目均已核验 |
| `cargo test --frozen -p traffic-engine --lib observability` | 0 | 17 项新增测试；全量入口中的 Rust 库测试合计 456 项通过 |
| `bash scripts/verify/check-aggregate-observability.sh --tshark` | 0 | 60 流，TCP 200／UDP 20，TLS／QUIC 候选各 20；重传／乱序各 20，20 个 4ms SYN 响应时差与 tshark 一致；反向验证通过 |
| `cargo clippy --frozen -p traffic-engine --all-targets --all-features -- -D clippy::correctness` | 0 | correctness 无错误；风格警告保留，未宣称零警告 |
| `RUSTDOCFLAGS='-D warnings' cargo doc --frozen --workspace --all-features --no-deps` | 0 | 文档构建通过 |
| actionlint／bash 语法／新增 Python Ruff、Black、py_compile／`git diff --check` | 0 | 通过 |
| Mermaid 语法与新增入口文档本地链接 | 0 | 1 张 Mermaid 图通过，文档链接存在 |
| `bash scripts/security/scan-secrets.sh` | 0 | 仓库兜底扫描命中 0 处；不是全面安全审计 |

本轮 BPF 经用户单独批准、在同一终端完成 sudo 认证，只有捕获子进程提权。en0 采集 15 秒取得 **1233 帧**，解析错误 0，tshark 帧数与写盘计数一致，自家回读为 1231 个 IP 帧＋2 个其他 L2 帧；前 500 帧经共享环消费数量一致，生成 85 条内部 Flow，合计 **14 项断言通过**。本机无可用网关注入目标，脚本没有发送 ping，ICMP 注入可见性断言未执行，不能写成 15 项通过。

新增入口又以普通用户读取本轮本机 PCAP，JSON 可解析、窗级记录守恒和必需尾记录通过：`input_complete=true`、`analysis_complete=true`、`capture_loss_status=unknown`。没有来源计数，未将 EOF 当作零丢包。此项只是实机文件回读，不是准确率或生产容量证明。原始抓包留本机 `build/e2e-live/`，聚合回读产物及日志留本机 `build/aggregate-observability/validation/`，不纳入 Git。

既有第三方裁判仍有 **DPI 14、TCP 重组 2、FlowRecord 8 项未核验**；本批没有改写这些判定。既有真实 ClickHouse D1／D2 均实跑通过，C++ 6 个 CTest 和前端 32 个测试通过。GitHub Actions 接线已做静态验证，未推送，远端矩阵尚未运行。

## 边界

仅离线 classic Ethernet PCAP。本批没有 VPN 指纹采样或公共用户识别／阻断，没有 UDP／加密承载的 RTT 推测，没有吞吐／生产链路能力证明。小流数抑制不等于用户匿名性或差分隐私。流量缺口不能直接解释为网络丢包，正常 EOF 不能解释为采集零丢包。

原有工作区暂存改动和其他 worktree 保留；提交只落本地。完整门禁仍有上述未核验项，本批保留功能分支，不合入主分支、不推送。
