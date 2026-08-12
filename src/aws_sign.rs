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

fn sha256_hex(data: &str) -> String {
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

    let mut signed_headers_list = vec!["host", "x-amz-date"];
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
    canonical_headers.push_str(&format!("host:{host}\nx-amz-date:{datetime}\n"));
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
/// `SystemTime::now()` panics in `wasm32-unknown-unknown` — extism does not
/// expose a host clock to plugins. Instead, we fetch the current time from the
/// `Date` response header of an unsigned HEAD request to the regional STS
/// endpoint. STS is always reachable (it matches the `*.amazonaws.com`
/// allowed-host glob) and every HTTP/1.1 response includes a `Date` header.
#[cfg(target_arch = "wasm32")]
pub(crate) fn utc_now_iso8601(region: &str) -> String {
    use extism_pdk::{http, HttpRequest};

    let host = format!("sts.{region}.amazonaws.com");
    let url = format!("https://{host}/");
    let req = HttpRequest::new(&url)
        .with_method("HEAD")
        .with_header("Host", &host);

    if let Ok(resp) = http::request::<String>(&req, None::<String>) {
        // extism normalizes response header names to lowercase.
        if let Some(date) = resp.header("date") {
            if let Some(formatted) = parse_http_date(date) {
                return formatted;
            }
        }
    }

    // Fallback: should never be reached. An obviously-wrong timestamp causes
    // AWS to return RequestExpired, surfacing a clear error rather than a panic.
    "19700101T000000Z".to_string()
}

/// Parse an RFC 7231 HTTP `Date` header into AWS Sig V4 datetime format.
///
/// Input:  `"Tue, 12 Aug 2026 13:47:12 GMT"`
/// Output: `"20260812T134712Z"`
#[cfg(target_arch = "wasm32")]
fn parse_http_date(date: &str) -> Option<String> {
    let parts: Vec<&str> = date.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month: u32 = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u32 = parts[3].parse().ok()?;
    let time: Vec<&str> = parts[4].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let h: u32 = time[0].parse().ok()?;
    let m: u32 = time[1].parse().ok()?;
    let s: u32 = time[2].parse().ok()?;
    Some(format!("{year:04}{month:02}{day:02}T{h:02}{m:02}{s:02}Z"))
}
