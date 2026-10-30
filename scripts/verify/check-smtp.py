#!/usr/bin/env python3
"""B020 offline SMTP CLI/reference checks.

单包判定只看第一条 SMTP 消息（命令或一条多行应答）。本脚本用合成 pcap 覆盖
命令/应答语法、端口上下文、截断与预算；`--tshark` 时由 Wireshark 独立解出
同一批字节的命令与应答字段。合成语料不等于真实邮件流量或投递结果验收。
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


def frame(payload, sport=40000, dport=25, ipv6=False, ip_size=None):
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

    greeting = b"220 mail.example.com ESMTP Postfix\r\n"
    multiline = b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n"
    # (payload, sport, dport, confidence, tshark fields, tshark expected)
    cases = [
        (
            greeting,
            25,
            40000,
            "high",
            ["smtp.response.code", "smtp.rsp.parameter"],
            ["220", "mail.example.com ESMTP Postfix"],
        ),
        (
            b"EHLO client.example\r\n",
            40000,
            587,
            "high",
            ["smtp.req.command", "smtp.req.parameter"],
            ["EHLO", "client.example"],
        ),
        (
            b"MAIL FROM:<alice@example.com> SIZE=100\r\n",
            40000,
            25,
            "high",
            ["smtp.req.command", "smtp.req.parameter"],
            ["MAIL", "FROM:<alice@example.com> SIZE=100"],
        ),
        (
            b"RCPT TO:<bob@example.net>\r\n",
            40000,
            25,
            "high",
            ["smtp.req.command", "smtp.req.parameter"],
            ["RCPT", "TO:<bob@example.net>"],
        ),
        (b"DATA\r\n", 40000, 25, "medium", ["smtp.req.command"], ["DATA"]),
        (
            b"354 End data with <CR><LF>.<CR><LF>\r\n",
            25,
            40000,
            "medium",
            ["smtp.response.code"],
            ["354"],
        ),
        (
            multiline,
            25,
            40000,
            "medium",
            ["smtp.response.code", "smtp.rsp.parameter"],
            ["250", "mail.example.com,PIPELINING,SIZE 10240000,STARTTLS"],
        ),
        # Wireshark 4.6 把 STARTTLS 显示成 `STAR`/`TLS`（它按前 4 字节取命令），
        # 这是第三方展示口径而非协议事实；该用例只做本地判定，不拿它当对照证据。
        (b"STARTTLS\r\n", 40000, 587, "medium", [], []),
        (
            b"AUTH PLAIN AGV4YW1wbGU=\r\n",
            40000,
            587,
            "medium",
            ["smtp.req.command", "smtp.req.parameter"],
            ["AUTH", "PLAIN AGV4YW1wbGU="],
        ),
        (
            b"BDAT 1024 LAST\r\n",
            40000,
            587,
            "medium",
            ["smtp.req.command", "smtp.req.parameter"],
            ["BDAT", "1024 LAST"],
        ),
        (b"QUIT\r\n", 40000, 25, "medium", ["smtp.req.command"], ["QUIT"]),
        (b"221 2.0.0 Bye\r\n", 25, 40000, "medium", ["smtp.response.code"], ["221"]),
    ]
    positive = 0
    negative = 0
    with tempfile.TemporaryDirectory(prefix="cythsec-smtp-") as tmp:
        path = Path(tmp) / "smtp.pcap"
        for ipv6 in (False, True):
            for index, (
                payload,
                sport,
                dport,
                confidence,
                names,
                expected,
            ) in enumerate(cases):
                pcap(path, frame(payload, sport, dport, ipv6))
                actual = rows(path)
                assert len(actual) == 1, actual
                app = actual[0]["app"]
                assert app["app"] == "smtp" and app["app_id"] == 65565, (index, app)
                assert app["confidence"] == confidence, (index, app)
                if index == 0:
                    assert rows(path, "--workers", "2") == actual
                if args.tshark and names:
                    assert fields(path, names) == expected, (
                        index,
                        fields(path, names),
                        expected,
                    )
                positive += 1

        # 只有第一条消息参与判定；流水线里的后续命令不得改变首条结论。
        pcap(
            path,
            frame(b"EHLO client.example\r\nMAIL FROM:<alice@example.com>\r\nDATA\r\n"),
        )
        tail = rows(path)
        assert tail[0]["app"]["app"] == "smtp" and tail[0]["app"]["rationale"].startswith("smtp greeting command")
        positive += 1

        negatives = [
            frame(greeting, 21, 40000),  # FTP 端口上的同名应答
            frame(greeting, 465, 40000),  # 隐式 TLS 端口不放行明文 SMTP
            frame(greeting, 993, 40000),
            frame(greeting, 40000, 80),
            frame(b"\x16\x03\x01\x00\x05hello", 40000, 587),
            frame(b"SSH-2.0-OpenSSH_9.6\r\n"),
            frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            frame(b"+OK POP3 ready\r\n"),
            frame(b"* OK IMAP ready\r\n"),
            frame(b"EHLO client.example\n"),  # 裸 LF
            frame(b"MAIL FROM: alice@example.com\r\n"),
            frame(b"MAIL FROM:<a b>\r\n"),
            frame(b"EHLO bad domain\r\n"),
            frame(b"DATA payload\r\n"),
            frame(b"AUTH\r\n"),
            frame(b"250-a\r\n251 b\r\n"),
            frame(b"999 nope\r\n"),
            frame(b"\x00\x01\x02\x03"),
            frame(b"X" * 3000),
            frame(b"QUIT\r\n", ip_size=10),
        ]
        for packet in negatives:
            pcap(path, packet)
            actual = rows(path)
            assert all(row["app"]["app"] != "smtp" for row in actual), actual
            negative += 1

        # 每个截断点都只能是"还没到"，不能被猜成已识别。
        for end in range(1, len(greeting)):
            pcap(path, frame(greeting[:end], 25, 40000))
            actual = rows(path)
            assert all(row["app"]["app"] != "smtp" for row in actual), (end, actual)
            negative += 1

        pcap(path, frame(multiline[:50], 25, 40000))
        assert rows(path)[0]["app"]["outcome"] == "need_more", rows(path)
        pcap(path, frame(greeting, 25, 40000))
        assert rows(path, "--inspect-bytes", "10")[0]["app"]["outcome"] == "need_more"
    print(
        f"B020 SMTP: {positive} positive / {negative} negative CLI cases and inspection budget passed; "
        + ("tshark commands/replies matched" if args.tshark else "independent reference not requested")
    )


if __name__ == "__main__":
    main()
