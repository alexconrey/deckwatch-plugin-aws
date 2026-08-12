//! AWS Signature Version 4 signing for WASM plugins.
//!
// The crypto and signing functions below are only called from WASM-only modules
// (iam, rds, s3, backup). On native host builds they appear unused, so suppress
// the lint here rather than sprinkling cfg attributes across every helper.
#![allow(dead_code)]
//!
//! Implements the signing algorithm using only pure-Rust crates (hmac + sha2)
//! that compile to wasm32-unknown-unknown without WASI.
//!
//! Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_hex(data: &str) -> String {
    hex(&Sha256::digest(data.as_bytes()))
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date);
    let k_region = hmac_sha256(&k_date, region);
    let k_service = hmac_sha256(&k_region, service);
    hmac_sha256(&k_service, "aws4_request")
}

/// Build the `Authorization` header value for an AWS Signature V4 request.
///
/// - `method`        — HTTP method (e.g. `"PUT"`)
/// - `host`          — the service hostname (e.g. `"s3.us-east-1.amazonaws.com"`)
/// - `path`          — URI path (e.g. `"/my-bucket"`)
/// - `query`         — canonical query string (e.g. `"versioning"`, empty for POST body requests)
/// - `body`          — request body (XML, URL-encoded, or empty)
/// - `datetime`      — `YYYYMMDDTHHmmSSZ` — must match `X-Amz-Date` header
/// - `region` / `service` — e.g. `"us-east-1"` / `"s3"`
/// - `access_key` / `secret_key` / `session_token`
/// - `content_type` — `Some("application/xml")` or `Some("application/x-www-form-urlencoded")`
///   for requests with a body; `None` to omit the `Content-Type` header from
///   the signed headers (appropriate for HEAD requests).
#[allow(clippy::too_many_arguments)]
pub fn authorization_header(
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    body: &str,
    datetime: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    content_type: Option<&str>,
) -> String {
    let date = &datetime[..8]; // YYYYMMDD

    // ── Canonical request ─────────────────────────────────────────────────────
    let payload_hash = sha256_hex(body);

    let mut signed_headers_list = vec!["host", "x-amz-content-sha256", "x-amz-date"];
    if content_type.is_some() {
        signed_headers_list.push("content-type");
    }
    if session_token.is_some() {
        signed_headers_list.push("x-amz-security-token");
    }
    signed_headers_list.sort();
    let signed_headers = signed_headers_list.join(";");

    let mut canonical_headers = String::new();
    if let Some(ct) = content_type {
        canonical_headers.push_str(&format!("content-type:{ct}\n"));
    }
    canonical_headers.push_str(&format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{datetime}\n"
    ));
    if let Some(tok) = session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{tok}\n"));
    }

    let canonical_request =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    // ── String to sign ────────────────────────────────────────────────────────
    let credential_scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
        sha256_hex(&canonical_request)
    );

    // ── Signature ─────────────────────────────────────────────────────────────
    let key = signing_key(secret_key, date, region, service);
    let signature = hex(&hmac_sha256(&key, &string_to_sign));

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    )
}

/// UTC datetime in the `YYYYMMDDTHHmmSSZ` format required by AWS Sig V4.
///
/// Calls the `now()` host function provided by deckwatch (registered via
/// `extism::Function` at `Plugin::new` time). This avoids both the
/// `SystemTime::now()` panic (`wasm32-unknown-unknown` has no system clock)
/// and the previous STS HEAD network round-trip approach (which failed when
/// multi-level GovCloud hostnames were not in `allowed_hosts`).
///
/// The `region` parameter is retained for API compatibility but is no longer
/// used — the host clock is region-agnostic.
#[cfg(target_arch = "wasm32")]
pub(crate) fn utc_now_iso8601(_region: &str) -> String {
    #[link(wasm_import_module = "extism:host/user")]
    unsafe extern "C" {
        fn now() -> i64;
    }
    let secs = unsafe { now() } as u64;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z")
}

/// Convert days since Unix epoch to (year, month, day). Proleptic Gregorian calendar.
/// Used by `utc_now_iso8601` on the WASM target where `chrono`/`time` crates
/// are unavailable without WASI.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_known_dates() {
        // Unix epoch: day 0 = 1970-01-01
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-08-12: days since epoch
        let days_2026_08_12: i64 =
            (2026 - 1970) * 365 + 14 + 31 + 28 + 31 + 30 + 31 + 30 + 31 + 12 - 1;
        // Just verify it's in the right ballpark (year 2026, month 8)
        let (y, mo, _d) = civil_from_days(days_2026_08_12);
        assert_eq!(y, 2026);
        assert_eq!(mo, 8);
    }
}
