// CYS-TRF-028 parity driver: no alternative feature implementation here.
// Cases are compiled into the executable; missing fixtures fail compilation.
use traffic_engine::feature::{FeatureExtractor, FlowSample, FEATURE_NAMES};
use traffic_engine::tcp::Side;

fn main() {
    let fixtures = include_str!("../../../tests/fixtures/feature-samples.tsv");
    let mut extractor = FeatureExtractor::default();
    let mut name = "";
    for line in fixtures.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["case", id, capacity] => {
                assert!(name.is_empty(), "nested case");
                name = id;
                extractor = FeatureExtractor::new(capacity.parse().expect("IAT capacity"));
            }
            ["end"] => {
                assert!(!name.is_empty(), "end without case");
                let vector = extractor.vector();
                assert!(vector.is_finite());
                println!(
                    "{{\"case\":\"{}\",\"schema_version\":{},\"names\":{:?},\"values\":{:?}}}",
                    name, vector.schema_version, FEATURE_NAMES, vector.values
                );
                name = "";
            }
            [side, length, timestamp, hex] => {
                assert!(!name.is_empty(), "sample without case");
                let side = match *side {
                    "A" => Side::A,
                    "B" => Side::B,
                    _ => panic!("canonical side must be A/B"),
                };
                let payload: Vec<u8> = if *hex == "-" {
                    Vec::new()
                } else {
                    assert_eq!(hex.len() % 2, 0);
                    (0..hex.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("payload hex"))
                        .collect()
                };
                extractor.observe(&FlowSample {
                    side,
                    payload_len: length.parse().expect("u32 length"),
                    timestamp_us: timestamp.parse().expect("u64 timestamp"),
                    payload: &payload,
                });
            }
            [] => (),
            _ => panic!("invalid fixture: {line}"),
        }
    }
    assert!(name.is_empty(), "unterminated fixture case");
}
