#!/usr/bin/env python3
"""Independent pcap/CLI/reference checks. Synthetic wire samples are not product accuracy evidence."""

import argparse
import importlib.util
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target/debug/cythsec-identify"


def run(args, expected=0):
    p = subprocess.run([str(a) for a in args], text=True, capture_output=True)
    if p.returncode != expected:
        raise AssertionError(f"{args[0]} exit={p.returncode}, expected={expected}: {p.stderr[-1500:]}")
    return p.stdout


def frame(data, proto=17, sport=12345, dport=51820, reverse=False):
    src = bytes([192, 0, 2, 1])
    dst = bytes([198, 51, 100, 2])
    if reverse:
        src, dst = dst, src
        sport, dport = dport, sport
    udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data if proto == 17 else data
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, proto, 0, src, dst))
    words = struct.unpack("!10H", ip)
    s = sum(words)
    s = (s & 65535) + (s >> 16)
    s = (s & 65535) + (s >> 16)
    ip[10:12] = struct.pack("!H", (~s) & 65535)
    return bytes(12) + b"\x08\x00" + ip + udp


def wg(kind, index, peer=0):
    p = bytearray(148 if kind == 1 else 92)
    p[0] = kind
    p[4:8] = struct.pack("<I", index)
    if kind == 2:
        p[8:12] = struct.pack("<I", peer)
    return p


def pcap(path, frames):
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack("<IIII", 1, i * 100, len(p), len(p)) + p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", action="store_true")
    a = ap.parse_args()
    run(["python3", ROOT / "tools/codegen/gen-vpn-protocols.py", "--check"])
    entries = json.loads((ROOT / "configs/registry/vpn-protocols.json").read_text())["entries"]
    catalog = run([BIN, "--catalog"])
    assert len(catalog.splitlines()) == len(entries)
    with tempfile.TemporaryDirectory(prefix="cythsec-vpn-") as tmp:
        d = Path(tmp)

        spec = importlib.util.spec_from_file_location("vpn_codegen", ROOT / "tools/codegen/gen-vpn-protocols.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = json.loads((ROOT / "configs/registry/vpn-protocols.json").read_text())
        altered = d / "catalog.json"
        module.CATALOG = altered
        for mutation in ("missing", "duplicate", "vendor", "orphan"):
            candidate = json.loads(json.dumps(source))
            if mutation == "missing":
                candidate["entries"] = [e for e in candidate["entries"] if e["id"] != "V021"]
            elif mutation == "duplicate":
                candidate["entries"].append(candidate["entries"][0])
            elif mutation == "vendor":
                next(e for e in candidate["entries"] if e["id"] == "C001")["name"] = "wrong vendor"
            else:
                candidate["entries"][0]["parent"] = "NOT-REGISTERED"
            altered.write_text(json.dumps(candidate, ensure_ascii=False))
            try:
                module.outputs()
            except ValueError:
                pass
            else:
                raise AssertionError("catalog guard accepted " + mutation)
        capture = d / "wireguard.pcap"
        pcap(capture, [frame(wg(1, 17)), frame(wg(2, 99, 17), reverse=True)])
        rows = [json.loads(s) for s in run([BIN, "-r", capture]).splitlines()]
        assert any(r["protocol_id"] == "V021" and r["confidence_level"] == "A" for r in rows)
        assert all(r["vendor_product"] is None for r in rows)
        # Mutate the peer index only: both packets retain their wire shape, but pairing must fail.
        pcap(capture, [frame(wg(1, 17)), frame(wg(2, 99, 18), reverse=True)])
        assert all(json.loads(s)["confidence_level"] != "A" for s in run([BIN, "-r", capture]).splitlines())
        # Random UDP/443 is neither Hysteria nor TUIC; no wildcard evidence is imported.
        pcap(capture, [frame(bytes([0x80]) * 148, dport=443)])
        rows = [json.loads(s) for s in run([BIN, "-r", capture]).splitlines()]
        assert rows[0]["protocol_id"] is None
        evidence = d / "attested.tsv"

        def write_context(roots=("edr", "gateway"), ids=("one", "two"), end=1_000_500):
            evidence.write_text(
                "\n".join(
                    "\t".join(
                        [
                            ids[i],
                            roots[i],
                            kind,
                            "P014",
                            "v2-test",
                            "quic",
                            "192.0.2.1",
                            "12345",
                            "198.51.100.2",
                            "443",
                            "17",
                            "1000000",
                            str(end),
                            "assert",
                        ]
                    )
                    for i, kind in enumerate(["endpoint", "gateway"])
                )
                + "\n"
            )

        write_context()
        rows = [json.loads(s) for s in run([BIN, "-r", capture, "--trusted-evidence", evidence]).splitlines()]
        assert any(
            r["protocol_id"] == "P014" and r["confidence_level"] == "B" and len(r["evidence_ids"]) == 2 for r in rows
        )
        write_context(roots=("same", "same"))
        assert all(
            json.loads(s)["confidence_level"] != "B"
            for s in run([BIN, "-r", capture, "--trusted-evidence", evidence]).splitlines()
        )
        write_context(ids=("one", "one"))
        run([BIN, "-r", capture, "--trusted-evidence", evidence], 2)
        evidence.write_text("bad\tfields\n")
        run([BIN, "-r", capture, "--trusted-evidence", evidence], 2)
        bad = d / "bad.pcap"
        bad.write_bytes(capture.read_bytes()[:-2])
        run([BIN, "-r", bad], 2)
        run([BIN, "-r", capture, "-o", capture], 2)
        print(f"VPN CLI: catalog {len(entries)}; pcap pairing/mutation/context quorum/negative inputs passed")
        if a.tshark:
            pcap(capture, [frame(wg(1, 17)), frame(wg(2, 99, 17), reverse=True)])
            fields = run(
                [
                    "tshark",
                    "-r",
                    capture,
                    "-d",
                    "udp.port==51820,wg",
                    "-T",
                    "fields",
                    "-e",
                    "wg.type",
                    "-e",
                    "wg.sender",
                    "-e",
                    "wg.receiver",
                ]
            )
            lines = [s.split("\t") for s in fields.splitlines()]
            assert [s[0] for s in lines] == ["1", "2"], fields
            assert int(lines[0][1], 0) == 17 and int(lines[1][1], 0) == 99 and int(lines[1][2], 0) == 17, fields
            # Native IP encapsulations are independently decoded without UDP port attribution.
            esp = bytes.fromhex("0000000100000001") + bytes(24)
            pcap(capture, [frame(esp, proto=50)])
            fields = run(
                [
                    "tshark",
                    "-r",
                    capture,
                    "-T",
                    "fields",
                    "-e",
                    "ip.proto",
                    "-e",
                    "esp.spi",
                    "-e",
                    "esp.sequence",
                ]
            )
            c = fields.strip().split("\t")
            assert c[0] == "50" and int(c[1], 0) == 1 and c[2] == "1", fields
            rows = [json.loads(s) for s in run([BIN, "-r", capture]).splitlines()]
            assert rows[0]["protocol_id"] == "V001" and rows[0]["confidence_level"] == "C"
            print(
                "VPN tshark reference: WireGuard type/sender/receiver and ESP proto/SPI/sequence agree; not MAC/ICV verification"
            )


if __name__ == "__main__":
    main()
