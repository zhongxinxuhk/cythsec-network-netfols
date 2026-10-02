#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-dpi-samples.py —— 生成 DPI 解析器的确定性测试向量

为什么是「生成器」而不是直接提交二进制 blob：
    DPI 解析器的测试向量必须能覆盖**畸形输入**（截断、长度字段撒谎、压缩指针成环），
    而畸形样本无法从真实流量里"碰巧采到"。生成器能精确控制每一个字节，且任何人
    在任何机器上运行都得到字节级一致的文件。

三方独立互证 —— 这是本目录的核心价值：
    1. **生成器**知道自己按什么参数构造了报文，据此算出期望值（不解析自己写出的字节，
       避免"自己解析自己"的循环论证）；
    2. **tshark** 是独立的第三方实现，用 `scripts/verify/check-dpi-vectors.sh` 复核
       SNI / JA3 / QNAME 与期望一致；
    3. **Rust 实现**读同一份 expected.json 做断言。
    三方中任意一方算错（或 JA3 规范理解偏差）都会被暴露。

产出（经典 pcap，LINKTYPE_ETHERNET=1，微秒精度，小端）：
    tls-vectors.pcap   TLS ClientHello 各类情形（含畸形），每报文一个不同五元组
    dns-vectors.pcap   DNS 查询/响应（含压缩指针与成环）
    http-vectors.pcap  HTTP 请求（Host 头提取）
    payloads/<名>.bin  上列每个报文的**原始 L7 载荷**（Rust 单测直接喂它，无需 pcap 解析）
    expected.json      期望值清单

用法：
    python3 datasets/dpi/generate-dpi-samples.py [输出目录]
"""

import hashlib
import json
import os
import struct
import sys

MAGIC_MICRO = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_DST = bytes.fromhex("001122334455")
ETH_SRC = bytes.fromhex("66778899aabb")
ETH_IPV4 = b"\x08\x00"

# GREASE 值（RFC 8701）：两个字节相同且低半字节为 0xa，形如 0x0a0a / 0x1a1a / 0x2a2a …
# 必须从 JA3 中排除，否则同一浏览器在不同连接上会算出不同指纹（GREASE 值随机变化）。
GREASE_VALUES = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
                 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA]


def cksum16(data: bytes) -> int:
    """标准 Internet 校验和（RFC 1071）。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(payload: bytes, ethertype: bytes = ETH_IPV4) -> bytes:
    return ETH_DST + ETH_SRC + ethertype + payload


def ipv4(payload: bytes, proto: int, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0)
    hdr += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    ck = cksum16(hdr)
    return hdr[:10] + struct.pack("!H", ck) + hdr[12:] + payload


def tcp4(payload: bytes, sport: int, dport: int, seq: int = 0x01020304,
         src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    """IPv4/TCP 报文。校验和正确计算 —— 校验和错的报文会被部分工具直接跳过，
    让"解析失败"与"工具不理它"混为一谈，排查时会走弯路。"""
    off_flags = (5 << 12) | 0x18  # data offset 5，PSH+ACK
    seg = struct.pack("!HHIIHHHH", sport, dport, seq, 0x05060708, off_flags, 0xFFFF, 0, 0)
    pseudo = bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    pseudo += struct.pack("!BBH", 0, 6, len(seg) + len(payload))
    ck = cksum16(pseudo + seg + payload)
    seg = seg[:16] + struct.pack("!H", ck) + seg[18:]
    return ipv4(seg + payload, 6, src, dst)


def udp4(payload: bytes, sport: int, dport: int,
         src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    pseudo += struct.pack("!BBH", 0, 17, length)
    ck = cksum16(pseudo + seg + payload)
    seg = seg[:6] + struct.pack("!H", ck) + seg[8:]
    return ipv4(seg + payload, 17, src, dst)


def pcap(frames) -> bytes:
    out = struct.pack("<IHHiIII", MAGIC_MICRO, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
    for ts_sec, ts_usec, frame, wirelen in frames:
        out += struct.pack("<IIII", ts_sec, ts_usec, len(frame), wirelen) + frame
    return out


# ---------------------------------------------------------------- TLS ClientHello

def ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def ext_server_name(host: str) -> bytes:
    n = host.encode("ascii")
    return ext(0x0000, struct.pack("!H", 3 + len(n)) + b"\x00" + struct.pack("!H", len(n)) + n)


def ext_supported_groups(groups) -> bytes:
    return ext(0x000A, struct.pack("!H", len(groups) * 2)
               + b"".join(struct.pack("!H", g) for g in groups))


def ext_ec_point_formats(fmts) -> bytes:
    return ext(0x000B, bytes([len(fmts)]) + bytes(fmts))


def ext_sig_algs(algs) -> bytes:
    return ext(0x000D, struct.pack("!H", len(algs) * 2)
               + b"".join(struct.pack("!H", a) for a in algs))


def ext_alpn(protos) -> bytes:
    inner = b"".join(bytes([len(p)]) + p for p in protos)
    return ext(0x0010, struct.pack("!H", len(inner)) + inner)


def ext_generic(etype: int) -> bytes:
    """空体扩展（用于 padding / ECH 等只需占位的场景）。"""
    return ext(etype, b"")


def client_hello(host=None, alpn=None, ciphers=None, groups=None, fmts=(0, 1),
                 extra_exts=(), version=0x0303, handshake_len_delta=0):
    """构造 ClientHello 字节流。

    handshake_len_delta 用于制造"长度字段撒谎"：正值让握手长度大于实际字节数。
    """
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C, 0x009D]
    if groups is None:
        groups = [0x001D, 0x0017, 0x0018]

    extbody = b""
    if host is not None:
        extbody += ext_server_name(host)
    if alpn:
        extbody += ext_alpn(alpn)
    extbody += ext_supported_groups(groups)
    extbody += ext_ec_point_formats(fmts)
    extbody += ext_sig_algs([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601])
    for e in extra_exts:
        extbody += e

    body = struct.pack("!H", version)
    body += bytes(range(32))                       # random
    body += b"\x00"                                # session_id 长度 0
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"                            # 压缩方法：长度 1，null
    body += struct.pack("!H", len(extbody)) + extbody

    hs = b"\x01" + struct.pack("!I", len(body) + handshake_len_delta)[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def ja3_of(version, ciphers, exts, groups, fmts) -> str:
    """按 JA3 规范计算指纹（Salesforce 定义）。

    注意各字段**空值要留空**而不是填占位符 —— 这一点算错会让所有"无扩展"的
    客户端指纹集体偏离参考实现。
    """
    def join(vals):
        keep = [str(v) for v in vals if v not in GREASE_VALUES]
        return "-".join(keep)

    raw = ",".join([str(version), join(ciphers), join(exts), join(groups), join(fmts)])
    return raw, hashlib.md5(raw.encode("ascii")).hexdigest()


def tls_case(name, payload: bytes, expect: str, tshark_verified=True,
             tshark_note=None, **kw):
    """组装一个 TLS 用例：期望值由**构造参数**推出，不解析 payload。

    tshark_verified 用于标注「这一条**无法**用 tshark 交叉核验」。
    三方互证的价值建立在"每条都有独立实现复核"上；若某条静默跳过核验，
    它就成了只有生成器一个证据的独白。因此这里必须**显式**标出来、写清原因，
    而不是让它悄悄失去交叉验证。
    """
    ciphers = kw.get("ciphers")
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C, 0x009D]
    groups = kw.get("groups")
    if groups is None:
        groups = [0x001D, 0x0017, 0x0018]
    fmts = list(kw.get("fmts", (0, 1)))
    host = kw.get("host")
    alpn = kw.get("alpn")
    extra = list(kw.get("extra_exts", ()))

    exts = []
    if host is not None:
        exts.append(0x0000)
    if alpn:
        exts.append(0x0010)
    exts.append(0x000A)
    exts.append(0x000B)
    exts.append(0x000D)
    exts += [struct.unpack("!H", e[:2])[0] for e in extra]

    entry = {
        "name": name,
        "payload_file": f"payloads/{name}.bin",
        "payload_len": len(payload),
        "expect": expect,
        "version": kw.get("version", 0x0303),
        "sni": host,
        "alpn": [a.decode() for a in alpn] if alpn else [],
        "ciphers": ciphers,
        "extensions": exts,
        "groups": groups,
        "ec_point_formats": fmts,
        # tshark 交叉核验标记：verified=False 的条目不参与 check-dpi-vectors.sh 的比对，
        # 原因写在 note 里（不是"没做"，是"这一条独立实现也判不出来"）。
        "tshark": {"verified": bool(tshark_verified), "note": tshark_note},
    }
    if expect == "identified":
        raw, digest = ja3_of(entry["version"], ciphers, exts, groups, fmts)
        entry["ja3"] = digest
        entry["ja3_raw"] = raw
    return entry, payload


def build_tls_cases():
    cases = []

    # 1. 常规 ClientHello（含 SNI + ALPN）
    payload = client_hello(host="example.com", alpn=[b"h2", b"http/1.1"])
    cases.append(tls_case("tls-basic", payload, "identified",
                          host="example.com", alpn=[b"h2", b"http/1.1"]))

    # 2. 无 SNI（隐私模式 / ECH）：仍是 TLS，但取不到 SNI —— 必须与"识别失败"区分
    payload = client_hello(host=None, alpn=[b"h2"])
    cases.append(tls_case("tls-no-sni", payload, "identified", host=None, alpn=[b"h2"]))

    # 3. 含 GREASE：指纹必须与"去掉 GREASE 后"一致，否则同一浏览器指纹不稳定
    grease_ciphers = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x1A1A]
    grease_groups = [0x2A2A, 0x001D, 0x0017, 0x0018]
    payload = client_hello(host="grease.example", alpn=[b"h2"],
                           ciphers=grease_ciphers, groups=grease_groups,
                           extra_exts=[ext_generic(0x3A3A)])
    cases.append(tls_case("tls-grease", payload, "identified", host="grease.example",
                          alpn=[b"h2"], ciphers=grease_ciphers, groups=grease_groups,
                          extra_exts=[ext_generic(0x3A3A)]))

    # 4. 分片：只给出前 60 字节。正确行为是「需要更多字节」而非「不认识」——
    #    省网里 TCP 分段导致 ClientHello 不完整极其常见，误判会污染应用识别统计。
    full = client_hello(host="fragmented.example", alpn=[b"h2"])
    cases.append(tls_case("tls-truncated", full[:60], "need_more",
                          host="fragmented.example", alpn=[b"h2"]))

    # 5. 握手长度字段撒谎（声称比实际长）：可能只是分片，故同样应报「需要更多字节」
    payload = client_hello(host="lying-len.example", alpn=[b"h2"], handshake_len_delta=200)
    cases.append(tls_case("tls-lying-handshake-len", payload, "need_more",
                          host="lying-len.example", alpn=[b"h2"]))

    # 6. 内层长度矛盾（握手长度自洽，但 cipher_suites 长度声称 200 实际只有 14）：
    #    这是真畸形，任何分片补齐都救不了，必须报 malformed。
    payload = bytearray(client_hello(host="bad-inner.example"))
    # 偏移量必须把**整个握手头的 4 字节**算进去：记录头 5 字节 + 握手头 4 字节，
    # 之后才是握手体（version 2 / random 32 / session_id_len 1）。
    # 早期版本写成 5+2+32+1=40，漏了 3 个字节，结果改坏的是 random 而不是 cipher_suites
    # 长度 —— 于是这条"畸形"样本其实完全合法，解析器正确地识别了它，
    # 而测试因为期望 malformed 才暴露出来。**畸形样本必须真的畸形**，否则它测的是空气。
    pos = 5 + 4 + 2 + 32 + 1
    payload[pos:pos + 2] = struct.pack("!H", 200)
    cases.append(tls_case("tls-bad-inner-len", bytes(payload), "malformed",
                          host="bad-inner.example"))

    # 7. 超长 SNI：确认长度处理不受 255 边界之外的直觉影响
    long_host = ("a" * 60 + ".") * 3 + "very-long-hostname.example"
    payload = client_hello(host=long_host, alpn=[b"h2"])
    cases.append(tls_case("tls-sni-long", payload, "identified", host=long_host, alpn=[b"h2"]))

    # 8. ECH 扩展（0xfe0d）存在但无外层 SNI：ECH 会把真实 SNI 加密，
    #    外层不可见 —— 应正常识别为 TLS 且 SNI 缺失，不能报错。
    #
    # 【已知的交叉核验例外】tshark 4.6.7 的 ECH 解析器对 draft 版本敏感：任何手工构造的
    # ECH 体（空体 / 4 字节 / 18 字节 / draft13 / config_id 单字节，均试过）都会被它判为
    # malformed，进而**抑制整包的 JA3**——连带连 SNI 也不给。这不是本向量的问题：
    # 未分配扩展 0x1234 带非空 body、以及 GREASE 扩展都能正常产出 JA3 且与自算一致，
    # 说明 tshark 只是拒收"它不认识的 ECH 格式"。
    # 按 JA3 规范，0xFE0D 就是个不透明扩展号、应计入 extensions 段，故本条期望值取
    # 生成器自算（ja3=5ed85fdff2e6244597c946c694915a30），**不模仿 tshark 放弃整包**。
    payload = client_hello(host=None, alpn=[b"h2"], extra_exts=[ext_generic(0xFE0D)])
    cases.append(tls_case("tls-ech-no-outer-sni", payload, "identified", host=None,
                          alpn=[b"h2"], extra_exts=[ext_generic(0xFE0D)],
                          tshark_verified=False,
                          tshark_note="tshark 4.6.7 的 ECH 解析器认不出手工构造的 ECH 体，"
                                      "会连整包 JA3 一起抑制；按 JA3 规范 0xFE0D 应为"
                                      "不透明扩展计入 extensions，故只做生成器自算，"
                                      "不跟随 tshark 放弃整包。"))

    # 9. 非 TLS 载荷（HTTP 请求）：作为 TLS 检测器的负例，防"看到 \x16 就当 TLS"
    http = (b"GET /index.html HTTP/1.1\r\n"
            b"Host: http.example.com\r\n"
            b"User-Agent: cythsec-dpi-test/1.0\r\n"
            b"Accept: */*\r\n\r\n")
    cases.append(tls_case("tls-negative-http", http, "not_tls", host=None))

    return cases


# ---------------------------------------------------------------- DNS

def dns_encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def dns_message(qname: str, qtype: int = 1, txid: int = 0x1234,
                qname_override: bytes = None) -> bytes:
    q = qname_override if qname_override is not None else dns_encode_name(qname)
    body = q + struct.pack("!HH", qtype, 1)
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + body


def dns_response(qname: str, txid: int = 0x5678, answer_name: bytes = None) -> bytes:
    """响应：ANSWER 的 NAME 用压缩指针指向 QUESTION 的 QNAME（偏移 12）。

    answer_name 可覆盖为任意字节，用于制造自指成环（指针指向自身）。
    """
    q = dns_encode_name(qname)
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    if answer_name is None:
        answer_name = b"\xC0\x0C"                 # 指向偏移 12（QUESTION 起点）
    ans = answer_name + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
    return hdr + q + struct.pack("!HH", 1, 1) + ans


def build_dns_cases():
    cases = []

    payload = dns_message("example.com")
    cases.append({"name": "dns-query-a", "expect": "identified", "qname": "example.com",
                  "qtype": 1, "payload": payload})

    payload = dns_message("www.host.example.org")
    cases.append({"name": "dns-query-multilabel", "expect": "identified",
                  "qname": "www.host.example.org", "qtype": 1, "payload": payload})

    # 长域名（接近 255 上限）：逐标签长度与总长都要正确处理
    long_name = ".".join(["segment%02d" % i for i in range(20)]) + ".example"
    payload = dns_message(long_name)
    cases.append({"name": "dns-query-long", "expect": "identified", "qname": long_name,
                  "qtype": 1, "payload": payload})

    # MX 查询：qtype 非 A 也要正确取 qname
    payload = dns_message("mail.example.net", qtype=15)
    cases.append({"name": "dns-query-mx", "expect": "identified", "qname": "mail.example.net",
                  "qtype": 15, "payload": payload})

    # 响应（ANSWER 用压缩指针）：解析 QNAME 不受影响，指针不得越界
    payload = dns_response("compressed.example.com")
    cases.append({"name": "dns-response-compressed", "expect": "identified",
                  "qname": "compressed.example.com", "qtype": 1, "payload": payload})

    # QUESTION 段出现压缩指针：真实实现不会这样发，属畸形 —— 必须拒绝，
    # 因为跟随指针会引入「指针成环 → 无限循环」的攻击面。
    payload = dns_message("", qname_override=b"\xC0\x0C" + b"\x00")
    cases.append({"name": "dns-question-pointer", "expect": "malformed", "qname": None,
                  "qtype": 1, "payload": payload})

    # 自指成环（指针指向自己）：若实现跟随指针且无跳数上限，这里会挂死。
    # 用例存在的唯一目的就是证明「不会挂死」。
    hdr = struct.pack("!HHHHHH", 0x9999, 0x0100, 1, 0, 0, 0)
    payload = hdr + b"\xC0\x0C" + b"\x00" + struct.pack("!HH", 1, 1)
    cases.append({"name": "dns-question-pointer-loop", "expect": "malformed", "qname": None,
                  "qtype": 1, "payload": payload})

    # 截断（只剩头部）：需要更多字节，不是畸形
    payload = dns_message("needmore.example")[:11]
    cases.append({"name": "dns-truncated", "expect": "need_more", "qname": None,
                  "qtype": 1, "payload": payload})

    # 负例：非 DNS 载荷
    payload = b"\xff\xff\xff\xff not a dns message at all"
    cases.append({"name": "dns-negative-garbage", "expect": "not_dns", "qname": None,
                  "qtype": 0, "payload": payload})

    return cases


# ---------------------------------------------------------------- HTTP

def build_http_cases():
    cases = []
    req = (b"GET /path?q=1 HTTP/1.1\r\nHost: api.example.com:8443\r\n"
           b"User-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
    cases.append({"name": "http-get-host", "expect": "identified", "method": "GET",
                  "host": "api.example.com", "payload": req})

    req = (b"POST /submit HTTP/1.1\r\nHost: form.example.net\r\n"
           b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
    cases.append({"name": "http-post-host", "expect": "identified", "method": "POST",
                  "host": "form.example.net", "payload": req})

    # 只有请求行、Host 尚未到达（分片）：应报 need_more 而非「无 Host」
    req = b"GET /early HTTP/1.1\r\nUser-Agent: curl/8.0\r\n"
    cases.append({"name": "http-no-host-yet", "expect": "need_more", "method": "GET",
                  "host": None, "payload": req})

    return cases


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else here
    paydir = os.path.join(outdir, "payloads")
    os.makedirs(paydir, exist_ok=True)

    manifest = {
        "generated_by": "datasets/dpi/generate-dpi-samples.py",
        "note": "期望值由构造参数推出（非解析产出）；SNI/JA3/QNAME 由 "
                "scripts/verify/check-dpi-vectors.sh 用 tshark 独立复核。"
                "tls[].tshark.verified=false 的条目属已知例外（仅生成器自算），"
                "原因见该字段的 note —— 未被核验的条目必须显式列出，不能默认通过。",
        "tls": [],
        "dns": [],
        "http": [],
    }

    # ---- TLS ----
    tls_cases = build_tls_cases()
    frames = []
    for i, (entry, payload) in enumerate(tls_cases):
        with open(os.path.join(outdir, entry["payload_file"]), "wb") as fh:
            fh.write(payload)
        frame = eth(tcp4(payload, 40000 + i, 443))
        frames.append((1700000100 + i, i * 1000, frame, len(frame)))
        manifest["tls"].append(entry)
    with open(os.path.join(outdir, "tls-vectors.pcap"), "wb") as fh:
        fh.write(pcap(frames))

    # ---- DNS ----
    dns_cases = build_dns_cases()
    frames = []
    for i, c in enumerate(dns_cases):
        rel = f"payloads/{c['name']}.bin"
        with open(os.path.join(outdir, rel), "wb") as fh:
            fh.write(c["payload"])
        frame = eth(udp4(c["payload"], 50000 + i, 53))
        frames.append((1700000200 + i, i * 1000, frame, len(frame)))
        manifest["dns"].append({
            "name": c["name"], "payload_file": rel, "payload_len": len(c["payload"]),
            "expect": c["expect"], "qname": c["qname"], "qtype": c["qtype"],
        })
    with open(os.path.join(outdir, "dns-vectors.pcap"), "wb") as fh:
        fh.write(pcap(frames))

    # ---- HTTP ----
    http_cases = build_http_cases()
    frames = []
    for i, c in enumerate(http_cases):
        rel = f"payloads/{c['name']}.bin"
        with open(os.path.join(outdir, rel), "wb") as fh:
            fh.write(c["payload"])
        frame = eth(tcp4(c["payload"], 41000 + i, 80))
        frames.append((1700000300 + i, i * 1000, frame, len(frame)))
        manifest["http"].append({
            "name": c["name"], "payload_file": rel, "payload_len": len(c["payload"]),
            "expect": c["expect"], "method": c["method"], "host": c["host"],
        })
    with open(os.path.join(outdir, "http-vectors.pcap"), "wb") as fh:
        fh.write(pcap(frames))

    mpath = os.path.join(outdir, "expected.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")

    total = len(manifest["tls"]) + len(manifest["dns"]) + len(manifest["http"])
    print(f"生成 {outdir}/tls-vectors.pcap   ({len(manifest['tls'])} 个 TLS 用例)")
    print(f"生成 {outdir}/dns-vectors.pcap   ({len(manifest['dns'])} 个 DNS 用例)")
    print(f"生成 {outdir}/http-vectors.pcap  ({len(manifest['http'])} 个 HTTP 用例)")
    print(f"生成 {outdir}/payloads/          ({total} 个载荷文件)")
    print(f"生成 {mpath}")


if __name__ == "__main__":
    main()
