//! Encoded environment channel over the kernel cmdline.
//!
//! Before the guest agent's gRPC socket exists, the kernel cmdline is the only
//! channel into the guest. But the kernel tokenizes it on spaces and hands each
//! `KEY=VALUE` token to init as an environment variable — a raw value that
//! contains spaces tears into bogus tokens, and the non-`KEY=VALUE` fragments
//! leak into init's argv, where clap rejects them and the agent dies before it
//! can even log (the VM then reports "failed to start").
//!
//! Container environment (image env + options env + secrets) therefore never
//! rides the cmdline at all — it reaches the guest through the gRPC socket's
//! `ContainerConfig` (see `container_rootfs.rs`, the single source of truth).
//! Only the agent's own bootstrap vars (RUST_LOG, RUST_BACKTRACE) need the
//! cmdline, and they travel encoded here.
//!
//! Wire format: one cmdline token `BOXLITE_ENV_ENC=<base64url(JSON object)>`.
//! The base64url alphabet contains no spaces, quotes, or padding `=`, so the
//! kernel passes the token through intact and the guest decodes it before
//! tracing init reads RUST_LOG.

use std::collections::BTreeMap;

/// Cmdline variable carrying the encoded bootstrap environment.
pub const CMDLINE_ENV_VAR: &str = "BOXLITE_ENV_ENC";

/// Encode an environment for the cmdline channel.
///
/// Returns `None` when `env` is empty — nothing should occupy the cmdline.
pub fn encode(env: &[(String, String)]) -> Option<String> {
    if env.is_empty() {
        return None;
    }
    let map: BTreeMap<&str, &str> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let json = serde_json::to_vec(&map).ok()?;
    Some(b64url_encode(&json))
}

/// Decode a [`CMDLINE_ENV_VAR`] value back into key-value pairs.
///
/// Returns keys in sorted order (BTreeMap semantics; the host-side builder's
/// FILO dedup guarantees keys are unique before encoding). Malformed input
/// yields an empty vec: the cmdline channel is best-effort — the guest must
/// boot regardless, it just loses its bootstrap vars.
pub fn decode(encoded: &str) -> Vec<(String, String)> {
    let json = b64url_decode(encoded);
    serde_json::from_slice::<BTreeMap<String, String>>(&json)
        .map(|map| map.into_iter().collect())
        .unwrap_or_default()
}

/// base64url alphabet (RFC 4648 §5), padding omitted — `=` is safe inside a
/// cmdline value but the shortest form keeps the size budget predictable.
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        let emitted = chunk.len() + 1;
        for i in 0..emitted {
            out.push(B64URL[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Vec<u8> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            match value(c) {
                Some(v) => n |= v << (18 - 6 * i),
                None => return Vec::new(),
            }
        }
        // A 2- or 3-char final chunk encodes fewer than 3 bytes: every bit of
        // the 24-bit group below the emitted bytes must be zero (a non-canonical
        // tail would let distinct inputs decode to the same output).
        let keep_bits = if chunk.len() == 4 { 24 } else { (chunk.len() - 1) * 8 };
        if n & ((1u32 << (24 - keep_bits)) - 1) != 0 {
            return Vec::new();
        }
        let emitted = if chunk.len() == 4 { 3 } else { chunk.len() - 1 };
        let be = n.to_be_bytes();
        out.extend_from_slice(&be[1..=emitted]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs<const N: usize>(items: [(&str, &str); N]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_env_encodes_to_none() {
        assert!(encode(&[]).is_none());
    }

    #[test]
    fn round_trips_values_that_tear_raw_cmdlines() {
        let env = pairs([
            ("RUST_LOG", "info,boxlite_guest=debug with spaces"),
            ("RUST_BACKTRACE", "full"),
        ]);
        let encoded = encode(&env).expect("non-empty env encodes");
        // The whole payload must be one cmdline-safe token: no spaces, quotes,
        // or equals anywhere.
        assert!(!encoded.contains(' '));
        assert!(!encoded.contains('"'));
        assert!(!encoded.contains('='));
        // decode returns keys sorted (BTreeMap).
        assert_eq!(decode(&encoded), pairs([("RUST_BACKTRACE", "full"), ("RUST_LOG", "info,boxlite_guest=debug with spaces")]));
    }

    #[test]
    fn round_trips_non_ascii_and_special_chars() {
        let env = pairs([
            ("RUST_LOG", "调试=中文 ✨"),
            ("WEIRD", "a\"b=c d,e\tf"),
        ]);
        assert_eq!(decode(&encode(&env).unwrap()), env);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        assert!(decode("not base64!").is_empty());
        assert!(decode("").is_empty());
        // Valid b64url whose plaintext is not JSON.
        let not_json = b64url_encode(b"definitely not json");
        assert!(decode(&not_json).is_empty());
    }

    #[test]
    fn decode_rejects_non_canonical_trailing_bits() {
        // 'A' encodes 6 zero bits as a 2-char group's first char — flip the
        // trailing bits by using 'B' (value 1) where a padded char would have
        // to carry zeros.
        assert!(b64url_decode("BB").is_empty());
        assert_eq!(b64url_decode("BA"), vec![0x04]);
    }
}
