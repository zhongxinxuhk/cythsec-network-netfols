// Package aggregate accepts only the aggregate-only cythsec-observe schema.
package aggregate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

const MaxBatchBytes = 1 << 20
const maxSafeInteger = 1<<53 - 1

var ErrInvalid = errors.New("invalid aggregate batch")

type Integrity struct {
	Records              uint64 `json:"records"`
	CapturedOctets       uint64 `json:"captured_octets"`
	WireOctets           uint64 `json:"wire_octets"`
	SnaplenTruncated     uint64 `json:"snaplen_truncated"`
	DecodedIP            uint64 `json:"decoded_ip"`
	NonIP                uint64 `json:"non_ip"`
	DecodeIncomplete     uint64 `json:"decode_incomplete"`
	UnparsedFragments    uint64 `json:"unparsed_fragments"`
	Unsupported          uint64 `json:"unsupported_or_bad_headers"`
	UnusableTransport    uint64 `json:"unusable_transport"`
	FragmentedTransport  uint64 `json:"fragmented_transport"`
	TimestampRegressions uint64 `json:"timestamp_regressions"`
	LateRecords          uint64 `json:"late_records"`
	UnsampledPackets     uint64 `json:"unsampled_packets"`
	SampledPackets       uint64 `json:"sampled_packets"`
	CapacityRejected     uint64 `json:"capacity_rejected_packets"`
}
type Quality struct {
	TCPFlows           uint64    `json:"sampled_tcp_flows"`
	Judged             uint64    `json:"judged_segments"`
	Retransmissions    uint64    `json:"retransmission_candidates"`
	OutOfOrder         uint64    `json:"out_of_order_candidates"`
	ForwardGaps        uint64    `json:"forward_gap_candidates"`
	AmbiguousSequences uint64    `json:"ambiguous_sequences"`
	ReusedTuples       uint64    `json:"reused_tuples"`
	AmbiguousResponses uint64    `json:"ambiguous_responses"`
	UnmatchedResponses uint64    `json:"unmatched_responses"`
	DelayBounds        []*uint64 `json:"response_delay_upper_bounds_ms"`
	DelaySamples       *uint64   `json:"response_delay_samples"`
	DelayHistogram     *[]uint64 `json:"response_delay_histogram"`
}
type Statistics struct {
	Flows     uint64    `json:"contributing_sampled_flows"`
	TCP       uint64    `json:"tcp_packets"`
	UDP       uint64    `json:"udp_packets"`
	Other     uint64    `json:"other_ip_packets"`
	TLS       *uint64   `json:"tls_record_candidate_packets"`
	QUIC      *uint64   `json:"quic_long_header_candidate_packets"`
	Integrity Integrity `json:"integrity"`
	Quality   *Quality  `json:"tcp_quality"`
}
type Window struct {
	Type       string      `json:"type"`
	Schema     uint64      `json:"schema_version"`
	Start      uint64      `json:"window_start_seconds"`
	Seconds    uint64      `json:"window_seconds"`
	Suppressed bool        `json:"suppressed"`
	Interval   uint64      `json:"sampling_interval"`
	Reason     string      `json:"reason,omitempty"`
	Statistics *Statistics `json:"statistics"`
}
type Status struct {
	Type             string  `json:"type"`
	Schema           uint64  `json:"schema_version"`
	InputComplete    bool    `json:"input_complete"`
	AnalysisComplete bool    `json:"analysis_complete"`
	Published        uint64  `json:"published_windows"`
	Suppressed       uint64  `json:"suppressed_windows"`
	Loss             string  `json:"capture_loss_status"`
	Consistent       *bool   `json:"source_counter_consistent"`
	Scope            *string `json:"source_scope"`
}
type Batch struct {
	Windows []Window
	Status  Status
}

// Go JSON otherwise silently treats missing/null scalar fields as zero. Enforce
// required fields recursively, preserving nullable fields and safe JS integers.
func shape(raw json.RawMessage, typ reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if typ.Kind() == reflect.Pointer {
			return nil
		}
		return ErrInvalid
	}
	if typ.Kind() == reflect.Pointer {
		return shape(raw, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			return ErrInvalid
		}
		for n := 0; n < typ.NumField(); n++ {
			f := typ.Field(n)
			tag := strings.Split(f.Tag.Get("json"), ",")
			v, ok := obj[tag[0]]
			if !ok {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return ErrInvalid
			}
			if err := shape(v, f.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			return ErrInvalid
		}
		for _, v := range list {
			if err := shape(v, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Uint64:
		var n uint64
		if json.Unmarshal(raw, &n) != nil || n > maxSafeInteger {
			return ErrInvalid
		}
	}
	return nil
}
func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return shape(raw, reflect.TypeOf(out).Elem())
}
func (w Window) validate() bool {
	if w.Type != "aggregate_window" || w.Schema != 1 || w.Seconds < 60 || w.Seconds > 3600 || w.Start%w.Seconds != 0 || w.Interval < 1 || w.Interval > 1_000_000 {
		return false
	}
	if w.Suppressed {
		return w.Statistics == nil && w.Reason == "insufficient_sampled_flow_cohort"
	}
	if w.Reason != "" || w.Statistics == nil {
		return false
	}
	s := w.Statistics
	i := s.Integrity
	if s.Flows < 20 || s.Flows > 65536 || s.Flows > i.SampledPackets || i.SampledPackets > i.DecodedIP || i.CapturedOctets > i.WireOctets || i.SnaplenTruncated > i.Records {
		return false
	}
	if i.Records != i.DecodedIP+i.NonIP+i.DecodeIncomplete+i.UnparsedFragments+i.Unsupported+i.LateRecords || i.DecodedIP != s.TCP+s.UDP+s.Other {
		return false
	}
	if (s.TLS != nil && (*s.TLS < 20 || *s.TLS > i.SampledPackets || *s.TLS > s.TCP)) || (s.QUIC != nil && (*s.QUIC < 20 || *s.QUIC > i.SampledPackets || *s.QUIC > s.UDP)) {
		return false
	}
	q := s.Quality
	if q == nil {
		return true
	}
	if q.TCPFlows < 20 || q.TCPFlows > s.Flows || q.TCPFlows > s.TCP || q.Judged > i.SampledPackets || q.Retransmissions+q.OutOfOrder+q.ForwardGaps > q.Judged {
		return false
	}
	bounds := []uint64{1, 5, 10, 25, 50, 100, 250, 1000, 30000}
	if len(q.DelayBounds) != 10 || q.DelayBounds[9] != nil {
		return false
	}
	for n, v := range bounds {
		if q.DelayBounds[n] == nil || *q.DelayBounds[n] != v {
			return false
		}
	}
	if q.DelaySamples == nil {
		return q.DelayHistogram == nil
	}
	if q.DelayHistogram == nil || *q.DelaySamples < 20 || *q.DelaySamples > q.TCPFlows || len(*q.DelayHistogram) != 10 {
		return false
	}
	var total uint64
	for _, n := range *q.DelayHistogram {
		total += n
	}
	return total == *q.DelaySamples
}
func (s Status) validate() bool {
	if s.Type != "capture_status" || s.Schema != 1 || (!s.InputComplete && s.AnalysisComplete) {
		return false
	}
	switch s.Loss {
	case "unknown":
		return s.Consistent == nil && s.Scope == nil
	case "declared_zero", "declared_nonzero":
		return s.Consistent != nil && *s.Consistent && s.Scope != nil && *s.Scope == "operator_declared_same_capture"
	case "inconsistent_counters":
		return s.Consistent != nil && !*s.Consistent && s.Scope != nil && *s.Scope == "operator_declared_same_capture"
	}
	return false
}

// Parse requires exactly one final status. Partial analysis can be archived, but
// its original completion flags remain visible; persistence is not acceptance.
func Parse(data []byte) (Batch, error) {
	var b Batch
	if len(data) > MaxBatchBytes {
		return b, ErrInvalid
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), MaxBatchBytes)
	ended := false
	var published, suppressed uint64
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if ended {
			return Batch{}, ErrInvalid
		}
		var tag struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(line, &tag) != nil {
			return Batch{}, ErrInvalid
		}
		switch tag.Type {
		case "aggregate_window":
			var w Window
			if decode(line, &w) != nil || !w.validate() || len(b.Windows) >= 1024 {
				return Batch{}, ErrInvalid
			}
			if n := len(b.Windows); n > 0 {
				prev := b.Windows[n-1]
				if w.Start < prev.Start+prev.Seconds || w.Seconds != prev.Seconds || w.Interval != prev.Interval {
					return Batch{}, ErrInvalid
				}
			}
			b.Windows = append(b.Windows, w)
			if w.Suppressed {
				suppressed++
			} else {
				published++
			}
		case "capture_status":
			if decode(line, &b.Status) != nil || !b.Status.validate() {
				return Batch{}, ErrInvalid
			}
			ended = true
		default:
			return Batch{}, ErrInvalid
		}
	}
	if scanner.Err() != nil || !ended || b.Status.Published != published || b.Status.Suppressed != suppressed {
		return Batch{}, ErrInvalid
	}
	for _, w := range b.Windows {
		if w.Statistics != nil && w.Statistics.Integrity.CapacityRejected > 0 && b.Status.AnalysisComplete {
			return Batch{}, ErrInvalid
		}
	}
	return b, nil
}
func canonical(b Batch) []byte {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	for _, w := range b.Windows {
		_ = enc.Encode(w)
	}
	_ = enc.Encode(b.Status)
	return out.Bytes()
}
