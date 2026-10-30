# 2026-10-26 真实采集回读计数守恒修复

独立分支 `fix/live-readback-counts`，起点为队列功能提交 `1788b14`。不修改 C++／Rust 报文解析算法，只修正 live 验收脚本的回读计数口径并增加可执行自证。

## 失败证据与根因

最终普通用户完整测试曾退出 1：采集与 tshark 均为 572 帧；C++ 统计为解析成功 569、不支持 2、解析失败／畸形 1。额外一帧是 IPv4 非首片，分片偏移 177，帧长 35；其数据不包含完整 UDP 头，解析器将它列为失败。

旧 C 段只计算“成功 IP＋不支持”，漏掉 CLI 明确报告的解析失败类别，因此 569＋2 ≠ 572。旧 D 段的 Rust／tshark 五元组裁判已经覆盖非首片，这是两个独立判据的口径差异，不能直接等同于写盘丢包。

## 修复

回读数量核验改为以下三项同时成立：

```text
CLI total == capture written（采集写盘总数也由 B 段 tshark 独立确认）
parsed + unsupported + malformed == total
IPv4_success + IPv6_success + Other_success == parsed
```

字段缺失、重复、非法、分类总数不一致或分布不一致都会失败；截断数必须不超过总数。使用逐行读取摘要，不因繁忙口逐包日志大而一次读入整个文件。结果保留 malformed 数，不将失败报文改写为成功。

计数守恒验证的是“每条记录都有解析结果”，不保证每包可解析，也不是协议准确率或零丢包证明。原有解析器单测和独立裁判继续存在。

新增自证调用真实 C++ 解析器处理三帧合成 PCAP：一个正常 UDP、一个 LLC 不支持帧、一个只有一字节数据的非首片。期望恰为 1 成功／1 不支持／1 失败，防止“全部归为失败”也被当作解析正常；另有 5 项计数或缺字段注入必须被拒绝。

## 验证

对保留的实际失败摘要核验退出 0，得到 total=572、parsed=569、malformed=1、unsupported=2；真实解析器三帧自证及 5 项注入退出 0。最终 `PATH=/tmp/cythsec-format-env/bin:$PATH bash scripts/lint/lint-all.sh` 退出 **0**；`CYTHSEC_LIVE_SUDO=0 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` 退出 **0**。最终 BPF 普通用户采集 15 秒取得 **5037 帧**，捕获解析错误 0；tshark 5037、C++ total=5037、parsed=5035、unsupported=2、malformed=0、truncated=0。共 **15 项断言通过**，比旧版增加一项离线回读自证；没有网关注入目标，ICMP 注入核验仍未执行。

最终门禁包含队列 SIGKILL／重放端到端与前端 48 项测试，已执行到结束。旧 DPI 14、TCP 重组 2、FlowRecord 8 项裁判例外保持未核验，不将命令退出 0 描述成所有项目均已独立核验。

当前用户已在 access_bpf 组，可以普通用户抓包，复验不再使用 sudo。初次用户批准的 BPF 复验记录仍保留；无可用网关时不执行 ping，也不把 ICMP 可见性算为已核验。原有第三方裁判例外不因本修复关闭。
