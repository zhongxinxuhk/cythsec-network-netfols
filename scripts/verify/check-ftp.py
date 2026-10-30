#!/usr/bin/env python3
"""B021 offline FTP control-channel CLI/reference checks.

单包判定只看首条 FTP 命令或首条应答（含 `code-`/`code SP` 多行格式）。
本脚本覆盖命令语法、应答码、端口上下文、截断与预算；`--tshark` 时由 Wireshark
独立解出同一批字节的命令/应答字段。合成语料不等于真实 FTP 会话或登录结果验收。
"""

import argparse
import ipaddress
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target/debug/cythsec-analyze"


def run(args):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{args[0]} exit={p.returncode}: {p.stderr[-1000:]}"
    return p.stdout


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(payload, sport=40000, dport=21, ipv6=False, ip_size=None):
    src = ipaddress.ip_address("2001:db8::1" if ipv6 else "192.0.2.1").packed
    dst = ipaddress.ip_address("2001:db8::2" if ipv6 else "198.51.100.2").packed
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
    size = len(tcp) if ip_size is None else ip_size
    if ipv6:
        ip = struct.pack("!IHBB", 6 << 28, size, 6, 64) + src + dst
        ethertype = b"\x86\xdd"
    else:
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, size + 20, 1, 0, 64, 6, 0, src, dst))
        ip[10:12] = struct.pack("!H", checksum(bytes(ip)))
        ethertype = b"\x08\x00"
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + ethertype + bytes(ip) + tcp


def pcap(path, packet):
    path.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(packet), len(packet))
        + packet
    )


def rows(path, *args):
    return [json.loads(line) for line in run([BIN, "-r", path, "-q", *args]).splitlines()]


def fields(path, names):
    args = ["tshark", "-r", path, "-T", "fields"]
    for name in names:
        args.extend(["-e", name])
    values = run(args).rstrip("\n").split("\t")
    assert len(values) == len(names), (names, values)
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tshark", action="store_true")
    args = parser.parse_args()

    greeting = b"220 (vsFTPd 3.0.5)\r\n"
    multiline = b"211-Features:\r\n UTF8\r\n MDTM\r\n211 End\r\n"
    # (payload, sport, dport, confidence, tshark fields, tshark expected)
    cases = [
        (greeting, 21, 40000, "high", ["ftp.response.code", "ftp.response.arg"], ["220", "(vsFTPd 3.0.5)"]),
        (b"220 FileZilla Server 1.8.0\r\n", 21, 40000, "medium", ["ftp.response.code"], ["220"]),
        (b"USER anonymous\r\n", 40000, 21, "high", ["ftp.request.command", "ftp.request.arg"], ["USER", "anonymous"]),
        # 口令只用于语法/对照；解析层对 PASS 恒不保留实参。
        (b"PASS x\r\n", 40000, 21, "high", ["ftp.request.command", "ftp.request.arg"], ["PASS", "x"]),
        (b"TYPE I\r\n", 40000, 21, "high", ["ftp.request.command", "ftp.request.arg"], ["TYPE", "I"]),
        (b"STRU F\r\n", 40000, 21, "high", ["ftp.request.command", "ftp.request.arg"], ["STRU", "F"]),
        (b"MODE S\r\n", 40000, 21, "high", ["ftp.request.command", "ftp.request.arg"], ["MODE", "S"]),
        (b"PORT 192,0,2,1,10,20\r\n", 40000, 21, "high", ["ftp.request.command"], ["PORT"]),
        (b"PASV\r\n", 40000, 21, "high", ["ftp.request.command"], ["PASV"]),
        (b"EPSV\r\n", 40000, 21, "high", ["ftp.request.command"], ["EPSV"]),
        (b"EPRT |1|192.0.2.1|12345|\r\n", 40000, 21, "high", ["ftp.request.command"], ["EPRT"]),
        (b"AUTH TLS\r\n", 40000, 21, "high", ["ftp.request.command", "ftp.request.arg"], ["AUTH", "TLS"]),
        (b"PBSZ 0\r\n", 40000, 21, "high", ["ftp.request.command"], ["PBSZ"]),
        (b"PROT P\r\n", 40000, 21, "high", ["ftp.request.command"], ["PROT"]),
        (b"REST 0\r\n", 40000, 21, "high", ["ftp.request.command"], ["REST"]),
        (b"RETR file name.txt\r\n", 40000, 21, "medium", ["ftp.request.command"], ["RETR"]),
        (b"STOR upload.bin\r\n", 40000, 21, "medium", ["ftp.request.command"], ["STOR"]),
        (b"CWD /pub\r\n", 40000, 21, "medium", ["ftp.request.command"], ["CWD"]),
        (b"PWD\r\n", 40000, 21, "medium", ["ftp.request.command"], ["PWD"]),
        (b"SYST\r\n", 40000, 21, "medium", ["ftp.request.command"], ["SYST"]),
        (b"FEAT\r\n", 40000, 21, "medium", ["ftp.request.command"], ["FEAT"]),
        (b"331 Please specify the password.\r\n", 21, 40000, "medium", ["ftp.response.code"], ["331"]),
        (b"230 Login successful.\r\n", 21, 40000, "medium", ["ftp.response.code"], ["230"]),
        (b"227 Entering Passive Mode (192,0,2,1,10,20).\r\n", 21, 40000, "medium", ["ftp.response.code"], ["227"]),
        (b"150 Opening BINARY mode data connection.\r\n", 21, 40000, "medium", ["ftp.response.code"], ["150"]),
        (b"226 Transfer complete.\r\n", 21, 40000, "medium", ["ftp.response.code"], ["226"]),
        # tshark 对 FTP 多行应答只显示首行文本；多行结构由本地解析器负责。
        (multiline, 21, 40000, "medium", ["ftp.response.code", "ftp.response.arg"], ["211", "Features:"]),
        (b"QUIT\r\n", 40000, 21, "medium", ["ftp.request.command"], ["QUIT"]),
    ]
    positive = 0
    negative = 0
    with tempfile.TemporaryDirectory(prefix="cythsec-ftp-") as tmp:
        path = Path(tmp) / "ftp.pcap"
        for ipv6 in (False, True):
            for index, (payload, sport, dport, confidence, names, expected) in enumerate(cases):
                pcap(path, frame(payload, sport, dport, ipv6))
                actual = rows(path)
                assert len(actual) == 1, actual
                app = actual[0]["app"]
                assert app["app"] == "ftp" and app["app_id"] == 65566, (index, app)
                assert app["confidence"] == confidence, (index, app)
                if index == 0:
                    assert rows(path, "--workers", "2") == actual
                if args.tshark and names:
                    assert fields(path, names) == expected, (index, fields(path, names), expected)
                positive += 1

        # 只取第一条消息；流水线命令不改变首条结论。
        pcap(path, frame(b"USER anonymous\r\nPASS x\r\nSYST\r\n"))
        tail = rows(path)
        assert tail[0]["app"]["app"] == "ftp" and tail[0]["app"]["rationale"] == "ftp login command"
        positive += 1

        negatives = [
            frame(greeting, 25, 40000),  # SMTP 端口上的 FTP 问候
            frame(greeting, 990, 40000),  # 隐式 FTPS 端口不放行明文 FTP
            frame(greeting, 992, 40000),
            frame(greeting, 40000, 80),
            frame(b"\x16\x03\x01\x00\x05hello", 40000, 21),
            frame(b"SSH-2.0-OpenSSH_9.6\r\n"),
            frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            frame(b"EHLO client.example\r\n"),
            frame(b"+OK POP3 ready\r\n"),
            frame(b"* OK IMAP ready\r\n"),
            frame(b"USER anonymous\n"),  # 裸 LF
            frame(b"USER\r\n"),
            frame(b"TYPE X\r\n"),
            frame(b"STRU X\r\n"),
            frame(b"PORT 1,2,3\r\n"),
            frame(b"PORT 1,2,3,4,5,256\r\n"),
            frame(b"EPRT |3|192.0.2.1|80|\r\n"),
            frame(b"REST abc\r\n"),
            frame(b"QUIT now\r\n"),
            frame(b"FEAT x\r\n"),
            frame(b"999 nope\r\n"),
            frame(b"600 nope\r\n"),
            frame(b"\x00\x01\x02\x03"),
            frame(b"X" * 3000),
            frame(b"PWD\r\n", ip_size=10),
        ]
        for packet in negatives:
            pcap(path, packet)
            actual = rows(path)
            assert all(row["app"]["app"] != "ftp" for row in actual), actual
            negative += 1

        # 每个截断点都只能是"还没到"，不能被猜成已识别。
        for end in range(1, len(greeting)):
            pcap(path, frame(greeting[:end], 21, 40000))
            actual = rows(path)
            assert all(row["app"]["app"] != "ftp" for row in actual), (end, actual)
            negative += 1

        pcap(path, frame(multiline[:22], 21, 40000))
        assert rows(path)[0]["app"]["outcome"] == "need_more", rows(path)
        pcap(path, frame(greeting, 21, 40000))
        assert rows(path, "--inspect-bytes", "10")[0]["app"]["outcome"] == "need_more"
    print(
        f"B021 FTP: {positive} positive / {negative} negative CLI cases and inspection budget passed; "
        + ("tshark commands/replies matched" if args.tshark else "independent reference not requested")
    )


if __name__ == "__main__":
    main()
