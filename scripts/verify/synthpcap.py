#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合成 pcap 与 IPFIX 产物的读写工具（关口共用）。

**为什么要共用一份**：`check-sampling.py` 与 `check-estimate.py` 都需要"造一批我知道
底细的流"。各写一份生成器的后果是两处会漂移：一边改了包长/时序，另一边的手算期望值
就悄悄不成立了 —— 而这种失效不会报错，只会让断言变成"永远通过"。

数据流：`make_flow_pcap` 造 TCP 会话 → `cythsec-analyze` 导出 JSONL/IPFIX pcap →
`patch_ie34`（故障注入用）在线路上伪造采样声明。
"""

import struct
import subprocess


def ip4(n):
    return bytes([10, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth_ip_tcp(payload, src, dst, sport, dport, flags=0x10):
    """最小以太/IPv4/TCP 帧（校验和按 RFC 793/791 实算，不是填 0）。"""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0) + payload
    src_ip, dst_ip = ip4(src), ip4(dst)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00" + ip + tcp


def write_pcap(path, frames, ts_base=1_700_000_000):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fh.write(struct.pack("<IIII", ts_base + i // 1000, (i % 1000) * 1000, len(fr), len(fr)))
            fh.write(fr)


def make_flow_pcap(path, flows, packets_per_flow=2, payload_base=64):
    """造 `flows` 条互不相同的 TCP 会话，**每条恰好 `packets_per_flow` 个包**。

    载荷长度随流号变化（`payload_base + (i % 7) * 16`）：**让各流大小不同**是有意的 ——
    估计量的方差取决于总体中各单位的取值分布；全等大小时方差式会退化成理想情形，
    掩盖"按流聚合"与"按包聚合"的差别。

    `packets_per_flow` 必须是偶数（半数带载荷的上行包 + 半数纯 ACK 的下行包），
    这样每条流的键相同、包数确定；调用方的手算期望值（"共 flows×packets_per_flow 个包"）
    才成立。返回**实际写入的包数**（由本函数的循环结构决定，不是猜的）。
    """
    if packets_per_flow < 2 or packets_per_flow % 2:
        raise ValueError("packets_per_flow 必须是 ≥2 的偶数")
    frames = []
    for n in range(1, flows + 1):
        size = payload_base + (n % 7) * 16
        for k in range(packets_per_flow // 2):
            body = bytes([0x41 + (n + k) % 26]) * size
            if k == 0:
                body = b"GET /f%05d HTTP/1.1\r\nHost: h%05d\r\n\r\n" % (n, n) + body
            frames.append(eth_ip_tcp(body, n, 0x8000 + n, 40000 + n, 80))
            frames.append(eth_ip_tcp(b"", 0x8000 + n, n, 80, 40000 + n, 0x10))
    write_pcap(path, frames)
    return len(frames)


def run(cmd):
    """跑一条命令；返回 (rc, stdout, stderr)。"""
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


# ---- IPFIX 线路层的故障注入：把 IE 34 改成别的值 ----
#
# 为什么用"改线路字节"来做注入：估计量**完全信任声明**，而"导出器在 IE 34 上撒谎"
# 是它唯一的盲区。只有真的把线路上的值改掉，才能验证这个盲区确实存在（以及它有多严重）——
# 换成"拿一个错的期望值去比"就是自证循环。

IPFIX_HEADER_LEN = 16
SET_HEADER_LEN = 4
# 本仓 v4 模板的记录长度与 IE 34 在记录内的偏移（见 src/ipfix/mod.rs 的字段表：
# src4,dst4,sport2,dport2,proto1,octets8,packets8,start8,end8,flowid8,sampling4 = 57，
# 采样间隔是最后一个字段 ⇒ 偏移 57-4 = 53）。
RECORD_LEN_V4 = 57
IE34_OFFSET_IN_RECORD = RECORD_LEN_V4 - 4
# 数据模板号：**必须与 src/ipfix/mod.rs 的 `TEMPLATE_ID_V4` 一致**（=256）。写错时
# patch 会"一条都没改到"——所以两个 patch 函数都把"改了 0 条"当失败返回，调用方必须断言 >0。
# （第一版这里写成 4001，那是异厂互操作实现用的号，于是注入静默失效。）
TEMPLATE_ID_V4 = 256


def _read_pcap(path):
    with open(path, "rb") as fh:
        data = fh.read()
    assert data[:4] == b"\xd4\xc3\xb2\xa1", "只支持小端经典 pcap"
    out = []
    off = 24
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from("<IIII", data, off)
        off += 16
        out.append((ts, tus, data[off : off + incl]))
        off += incl
    return out


def _write_pcap(path, recs):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, tus, fr in recs:
            fh.write(struct.pack("<IIII", ts, tus, len(fr), len(fr)))
            fh.write(fr)


def _udp_payload(frame):
    """取出 UDP 载荷（以太 + IPv4 + UDP，无 VLAN/无选项）。返回 (payload, 偏移) 或 None。"""
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return None
    ip_off = 14
    ihl = (frame[ip_off] & 0x0F) * 4
    if frame[ip_off + 9] != 17:
        return None
    udp_off = ip_off + ihl
    payload_off = udp_off + 8
    return frame[payload_off:], payload_off


def patch_ie34(path, new_value, inplace=True):
    """把 IPFIX 数据记录里的 samplingInterval 改成 `new_value`（模拟导出器撒谎）。

    只改**数据集里每条记录**的 IE 34（模板不动：模板里 IE 34 是长度 4 的字段规格，
    不含取值）。返回被改写的记录条数；返回 0 说明这条 pcap 里没有可改的记录（应判失败）。
    """
    recs = _read_pcap(path)
    patched = 0
    for idx, (ts, tus, frame) in enumerate(recs):
        got = _udp_payload(frame)
        if not got:
            continue
        payload, base = got
        frame = bytearray(frame)
        # 报文 = 16 字节头 + 若干 set；逐 set 走，只动 data set（setID = 模板号）。
        off = IPFIX_HEADER_LEN
        while off + SET_HEADER_LEN <= len(payload):
            set_id, set_len = struct.unpack_from("!HH", payload, off)
            if set_len < SET_HEADER_LEN or off + set_len > len(payload):
                break
            if set_id == TEMPLATE_ID_V4:
                body = off + SET_HEADER_LEN
                end = off + set_len
                while body + RECORD_LEN_V4 <= end:
                    pos = base + body + IE34_OFFSET_IN_RECORD
                    frame[pos : pos + 4] = struct.pack("!I", new_value)
                    patched += 1
                    body += RECORD_LEN_V4
            off += set_len
        recs[idx] = (ts, tus, bytes(frame))
    if patched and inplace:
        _write_pcap(path, recs)
    return patched


# 记录内字段偏移（本仓 v4 模板，见两条注释的字段表）：
# src4 dst4 sport2 dport2 proto1 octets8 packets8 start8 end8 flowid8 sampling4 = 57
FLOWID_OFFSET_IN_RECORD = 4 + 4 + 2 + 2 + 1 + 8 + 8 + 8 + 8  # = 45


def rewrite_flow_id(path, delta=1_000_000):
    """把每条记录的 flowId 改成不同值（模拟导出侧 flowId 不稳定/重放被当成新流）。

    去重键含 flowId ⇒ 改掉它就能让"同一批记录重放一遍"绕过去重。返回改写的记录条数。
    """
    recs = _read_pcap(path)
    patched = 0
    for idx, (ts, tus, frame) in enumerate(recs):
        got = _udp_payload(frame)
        if not got:
            continue
        payload, base = got
        frame = bytearray(frame)
        off = IPFIX_HEADER_LEN
        while off + SET_HEADER_LEN <= len(payload):
            set_id, set_len = struct.unpack_from("!HH", payload, off)
            if set_len < SET_HEADER_LEN or off + set_len > len(payload):
                break
            if set_id == TEMPLATE_ID_V4:
                body = off + SET_HEADER_LEN
                end = off + set_len
                while body + RECORD_LEN_V4 <= end:
                    pos = base + body + FLOWID_OFFSET_IN_RECORD
                    old_id = struct.unpack_from("!Q", frame, pos)[0]
                    frame[pos : pos + 8] = struct.pack("!Q", old_id + delta)
                    patched += 1
                    body += RECORD_LEN_V4
            off += set_len
        recs[idx] = (ts, tus, bytes(frame))
    if patched:
        _write_pcap(path, recs)
    return patched


def tshark_ie34(path):
    """用 tshark（唯一第三方真源）读 IE 34；tshark 缺席返回 None。"""
    rc, out, _ = run([
        "tshark", "-r", path, "-d", "udp.port==4739,cflow",
        "-T", "fields", "-e", "cflow.sampling_interval",
    ])
    if rc != 0:
        return None
    vals = []
    for line in out.splitlines():
        for tok in line.split(","):
            if tok.strip():
                vals.append(int(tok))
    return vals


def concat_pcaps(dst, *srcs):
    """把多个 pcap 的报文按顺序拼成一个（用于"混合采样间隔"这类注入）。"""
    recs = []
    for s in srcs:
        recs.extend(_read_pcap(s))
    _write_pcap(dst, recs)
    return len(recs)
