#!/usr/bin/env python3
"""Generate audited protocol docs and the dependency-free Rust catalog from one source."""

from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "configs/registry/vpn-protocols.json"


def outputs() -> dict[Path, str]:
    data = json.loads(CATALOG.read_text())
    entries = data["entries"]
    ids = [e["id"] for e in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate protocol ID")
    book = (ROOT / data["input"]).read_text()
    required = set(re.findall(r"^\| ([VPO]\d{3}) \|", book, re.M))
    if len(required) != 90 or not required.issubset(ids):
        raise ValueError("input numbered protocol coverage drift")
    by_id = {e["id"]: e for e in entries}

    for prefix, start, end in (("C", "## 5. ", "### 5.1"), ("F", "## 6. ", "## 7. ")):
        section = book.split(start, 1)[1].split(end, 1)[0]
        rows = []
        for line in section.splitlines():
            if not line.startswith("| "):
                continue
            cells = [x.strip().replace("**", "") for x in line.split("|")[1:-1]]
            if cells[0].startswith("---") or cells[0] in ("厂商/生态", "产品/厂商"):
                continue
            rows.append(cells[0] + " — " + cells[1] if prefix == "C" else cells[0])
        actual = [e["name"] for e in sorted(entries, key=lambda e: e["id"]) if re.fullmatch(prefix + r"\d{3}", e["id"])]
        if rows != actual:
            raise ValueError(f"{prefix} product matrix coverage drift")
    for e in entries:
        for field in (
            "name",
            "syntax",
            "state_machine",
            "negative",
            "active",
            "source",
        ):
            if not e.get(field):
                raise ValueError(f"{e['id']}: missing {field}")
        if e["parent"] and e["parent"] not in by_id:
            raise ValueError(f"{e['id']}: unknown parent")
    generated = {}
    for e in entries:
        pid = e["id"]
        parent = (
            f"母项：[{e['parent']}]({e['parent']}.md)。子项需要独立模式证据，母项命中不自动传播。"
            if e["parent"]
            else "本项直接对应目录对象；同一承载不自动归因其他产品或混淆层。"
        )
        status = (
            "有界结构解析（只支持下文声明的可见布局）；真实产品样本精度尚未测定"
            if e["implementation"] == "bounded_wire_parser"
            else "可信上下文关联已实现；未实现无条件密文唯一识别，真实型号/版本正样本待补"
        )
        refs = (
            "\n".join(f"- [原始规范]({s})" for s in e["sources"])
            or "- 依据输入手册的能力/可见性记录；未重新核实全部厂商SKU和私有线缆格式，不将资料级D当运行时结论。"
        )
        generated[
            ROOT / f"docs/protocols/{pid}.md"
        ] = f"""<!-- GENERATED: configs/registry/vpn-protocols.json; gen-vpn-protocols.py -->
# {pid} · {e['name']}

规则修订：`{data['revision']}`。对象层次：`{e['layer']}`。输入位置：{e['source']}。

{parent}

## 实现与观测边界

{status}。目录存在只表示覆盖了设计和关联接口，不代表真实样本召回率已通过。
运行时入口为 `cythsec-identify`，标准结构判据在 `dpi/wire.rs`，上下文裁决在
`identification/evidence.rs`。既有 DPI 接口仍保留四态语义；完整识别事件单独输出，不改写 FlowRecord ABI。

## 被动特征算法

1. **观测条件与帧约束**：{e['syntax']}
2. **会话与状态关联**：{e['state_machine']}
3. **反证与降级**：{e['negative']}
4. **输出维度**：本对象仅写 `{e['layer']}` 轴；传输、安全握手、隧道、接入架构、产品和混淆层分别保留。缺失值为 `null`，不以端口补齐。

TCP 先按序号重组连续前缀，再检查帧长；UDP 保留数据报边界。捕获截断、乱序缺口、未知版本、预算耗尽分别留痕。
分类状态为 `candidate / wire_confirmed / context_verified / unknown`。`candidate` 为C；只有指定解析器
完成相应双向标识校验才可给A；A表示观测到符合结构的交互，不表示密码学认证成功。
B要求同一目录ID/版本/模式的至少两个独立信任来源匹配实际五元组与时间窗；配置文件中的单方声明不够。
资料级D仅存在目录，不写成某条网络流已经命中。

## 统计特征与算法

采集 {', '.join(e['statistical_features'])}。令包长为带方向符号的 `l_i`，相邻到达间隔为 `dt_i`；
使用长度直方图、IAT分位数、burst游程和 `bytes_up/(bytes_down+1)` 作为候选特征。
比较目标样本与HTTPS/H3/WebRTC/SSH负样本的条件分布，按产品版本、链路和模式分层。
训练数据按设备/站点/时间拆分，不能让同一会话相邻包泄漏到测试集；用独立校准集标定阈值并报告每类混淆矩阵。

本轮未训练或部署该统计模型，不能输出虚构概率；端口、熵、长度、SNI/JA3/JA4或单IP均不能独立晋升A/B。

## 主动验证与补充遥测

{e['active']}

计划类型：`{e['probe_kind']}`。先由 `ProbePlanner` 校验精确IP/端口/目录ID允许列表、授权ID、过期时间、
单目标/全局预算和不超过3秒的超时，再生成 `executed=false` 的计划；没有内置网络扫描器或自动发包。
执行器属于宿主/受管实验环境，必须再次校验授权并回传结果。静默、超时、连接拒绝和fallback均只记录结果，不能证明协议不存在或认证成功。
成功探测最多是一种证据来源，不能用同一次响应派生的证书/页面/指纹冒充多个独立来源。

## 识别与证据流

```mermaid
flowchart TD
    P["实际帧与有界重组"] --> W["{pid} 结构和模式检查"]
    W --> C["候选及反证"]
    E["可信终端 / 网关 / 资产遥测"] --> J["五元组、时间窗、版本、独立来源匹配"]
    C --> J
    J --> R["分层结果及证据ID"]
    R --> U["不足则 unknown / candidate"]
```

## 验收设计

- 正样本：按具体版本/配置生成双向流，并保存脱敏终端/网关会话、时间和配置摘要；合成结构测试不能替代真实产品PCAP。
- 反例：{e['negative']}
- 边界：每个长度字段的0/最小值/越界/截断，方向反转、错标识、重复包、会话重用、超时和内存上限。
- 上下文：缺一来源、同源重复、错五元组、过期事件、不同版本/模式、相反结论和未知目录ID必须不能给B。
- 主动验证：无允许列表、过期授权、预算超限拒绝；计划不得自行产生网络副作用。
- 指标：分别报告precision/recall/FPR/unknown及P95资源成本；当前不宣称全协议实测准确率。

## 参考与维护

- [输入识别手册](../vpn_ztna_protocol_identification_2026.md)
- [引擎架构与运行契约](../architecture/vpn-ztna-identification.md)
{refs}

更新JSON真源后运行 `python3 tools/codegen/gen-vpn-protocols.py`，再以 `--check` 验证；不要单改生成文档。
"""
    rows = "\n".join(
        f"| [{e['id']}]({e['id']}.md) | {e['name'].replace('|', '/')} | {e['layer']} | {e['implementation']} |"
        for e in entries
    )
    generated[ROOT / "docs/protocols/README.md"] = f"""# VPN / ZTNA 逐项识别算法目录

修订 `{data['revision']}`；共 **{len(entries)}** 项独立文档。V/P/O原始编号90项全部覆盖；另含承载/认证、32项国内产品、19项海外产品和组合项拆分。
覆盖的是算法设计、结构解析或可信上下文关联接口；不代表全部私有协议可被无密钥纯DPI唯一识别。

真源：[vpn-protocols.json](../../configs/registry/vpn-protocols.json)。
[总体架构](../architecture/vpn-ztna-identification.md) · [输入手册](../vpn_ztna_protocol_identification_2026.md) · [开发与验收](../planning/VPN-ZTNA-20261026.md)

| ID | 对象 | 层次 | 实现路径 |
| --- | --- | --- | --- |
{rows}
"""

    def quoted(s):
        return json.dumps(s, ensure_ascii=False)

    rust = [
        "// Generated by tools/codegen/gen-vpn-protocols.py; do not edit.",
        "use super::CatalogEntry;",
        "pub const RULE_VERSION: &str = " + quoted(data["revision"]) + ";",
        "pub static CATALOG: &[CatalogEntry] = &[",
    ]
    for e in sorted(entries, key=lambda x: x["id"]):
        parent = "Some(" + quoted(e["parent"]) + ")" if e["parent"] else "None"
        raw = {
            "esp": [50],
            "ah": [51],
            "gre": [47],
            "ipip": [4],
            "ipv6ip": [41],
            "etherip": [97],
        }
        carrier = {
            "tcp": 6,
            "udp": 17,
            "tls": 6,
            "http": 6,
            "quic": 17,
            "dtls": 17,
            "ssh": 6,
            "tlcp": 6,
        }
        numbers = raw.get(e["detector"], sorted({carrier[c] for c in e["carriers"] if c in carrier}))
        protocols = "&[" + ", ".join(str(n) for n in numbers) + "]"
        rust.append(
            "    CatalogEntry {\n        id: "
            + quoted(e["id"])
            + ",\n        name: "
            + quoted(e["name"])
            + ",\n        layer: "
            + quoted(e["layer"])
            + ",\n        parser: "
            + quoted(e["detector"])
            + ",\n        ip_protocols: "
            + protocols
            + ",\n        parent: "
            + parent
            + ",\n    },"
        )
    rust.append("];\n")
    generated[ROOT / "dataplane/traffic-engine/src/identification/catalog_gen.rs"] = "\n".join(rust)
    return generated


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    wrong = []
    for p, text in outputs().items():
        if args.check:
            if not p.exists() or p.read_text() != text:
                wrong.append(str(p.relative_to(ROOT)))
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    if wrong:
        raise SystemExit("VPN catalog generated outputs stale: " + ", ".join(wrong))
    print("VPN catalog/docs: complete, unique and current")


if __name__ == "__main__":
    main()
