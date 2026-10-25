"""Training-side reference extractor for feature schema v1 (standard library only).

Input is an arrival-ordered stream of canonical-side L4 observations. This module
consumes the same observations as Rust; it does not parse pcap or infer direction.
Only the schema layout is generated. The numerical implementation is independent,
so the parity gate can detect a formula or observation-semantics drift.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from .schema_gen import FEATURE_COUNT, FEATURE_NAMES, FEATURE_SCHEMA_VERSION, SMALL_PACKET_MAX_LEN, idx


@dataclass(frozen=True)
class FlowSample:
    side: str
    payload_len: int
    timestamp_us: int
    payload: bytes = b''

    def __post_init__(self) -> None:
        if self.side not in ('A', 'B'):
            raise ValueError('side must be canonical A or B, not initiator direction')
        if type(self.payload_len) is not int or not 0 <= self.payload_len < 2**32:
            raise ValueError('payload_len must be u32')
        if type(self.timestamp_us) is not int or not 0 <= self.timestamp_us < 2**64:
            raise ValueError('timestamp_us must be u64')
        if not isinstance(self.payload, bytes):
            raise ValueError('payload must be bytes')


@dataclass(frozen=True)
class FeatureVector:
    schema_version: int
    values: tuple[float, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError('unsupported feature schema version')
        if len(self.values) != FEATURE_COUNT or not all(
            type(v) in (int, float) and math.isfinite(v) for v in self.values
        ):
            raise ValueError('feature vector must have the schema dimension and finite values')

    def by_name(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.values))


def _stddev(count: int, total: int, squares: int) -> float:
    if count < 2:
        return 0.0
    return math.sqrt(max(0.0, float(squares) / count - (float(total) / count) ** 2))


def extract(samples: Iterable[FlowSample]) -> FeatureVector:
    """Single-pass, bounded-memory extraction; all IATs contribute to aggregates."""
    packets = total = squares = fwd_packets = fwd_bytes = small = switches = 0
    first: int | None = None
    last: int | None = None
    prev: int | None = None
    prev_side: str | None = None
    min_len: int | None = None
    max_len: int | None = None
    iat_count = iat_sum = iat_squares = 0
    iat_min: int | None = None
    iat_max: int | None = None
    hist = [0] * 256
    for sample in samples:
        length, ts = sample.payload_len, sample.timestamp_us
        packets += 1
        total += length
        squares += length * length
        if sample.side == 'A':
            fwd_packets += 1
            fwd_bytes += length
        small += length <= SMALL_PACKET_MAX_LEN
        min_len = length if min_len is None else min(min_len, length)
        max_len = length if max_len is None else max(max_len, length)
        if first is None:
            first = ts
        last = ts if last is None else max(last, ts)
        if prev is not None:
            delta = max(0, ts - prev)
            iat_count += 1
            iat_sum = min(2**64 - 1, iat_sum + delta)
            iat_squares += delta * delta
            iat_min = delta if iat_min is None else min(iat_min, delta)
            iat_max = delta if iat_max is None else max(iat_max, delta)
        if prev_side is not None and prev_side != sample.side:
            switches += 1
        prev, prev_side = ts, sample.side
        for byte in sample.payload:
            hist[byte] += 1
    duration = max(0, last - first) if last is not None and first is not None else 0
    seconds = duration / 1_000_000.0
    entropy_bytes = sum(hist)
    entropy = 0.0
    if entropy_bytes:
        for count in hist:
            if count:
                p = count / entropy_bytes
                entropy -= p * math.log2(p)
    # A newly declared dimension must get an implementation; never silently zero-fill it.
    values: list[float | None] = [None] * FEATURE_COUNT
    values[idx.PACKETS] = float(packets)
    values[idx.BYTES] = float(total)
    values[idx.FWD_PACKETS] = float(fwd_packets)
    values[idx.FWD_BYTES] = float(fwd_bytes)
    values[idx.REV_PACKETS] = float(packets - fwd_packets)
    values[idx.REV_BYTES] = float(total - fwd_bytes)
    values[idx.FWD_BYTE_RATIO] = fwd_bytes / total if total else 0.0
    values[idx.DURATION_US] = float(duration)
    values[idx.BYTE_RATE_BPS] = total * 8.0 / seconds if seconds else 0.0
    values[idx.PACKET_RATE_PPS] = packets / seconds if seconds else 0.0
    values[idx.MEAN_PAYLOAD_LEN] = total / packets if packets else 0.0
    values[idx.MIN_PAYLOAD_LEN] = float(min_len or 0)
    values[idx.MAX_PAYLOAD_LEN] = float(max_len or 0)
    values[idx.STDDEV_PAYLOAD_LEN] = _stddev(packets, total, squares)
    values[idx.MEAN_IAT_US] = float(iat_sum // iat_count) if iat_count else 0.0
    values[idx.MIN_IAT_US] = float(iat_min or 0)
    values[idx.MAX_IAT_US] = float(iat_max or 0)
    values[idx.STDDEV_IAT_US] = _stddev(iat_count, iat_sum, iat_squares)
    values[idx.DIRECTION_SWITCHES] = float(switches)
    values[idx.SMALL_PACKET_RATIO] = small / packets if packets else 0.0
    values[idx.PAYLOAD_ENTROPY_BITS] = entropy
    complete: list[float] = []
    for value in values:
        if value is None:
            raise ValueError('feature dimension has no implementation')
        complete.append(value)
    return FeatureVector(FEATURE_SCHEMA_VERSION, tuple(complete))
