//! S3 bucket provisioning via the AWS S3 REST API.
//!
//! S3 uses a REST API (not the Query API). All bucket operations target the
//! regional endpoint `s3.<region>.amazonaws.com` using path-style addressing.
//! Responses are XML; requests with a body set `Content-Type: application/xml`.

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials, S3Config};

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure the S3 bucket exists, creating and configuring it if it does not.
///
/// Configuration applied on creation: versioning, public-access-block, and
/// lifecycle expiration. Existing buckets are left as-is to avoid overwriting
/// operator customisations.
pub fn ensure_bucket(
    cfg: &S3Config,
    full_bucket: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    // Attempt create directly — S3 CreateBucket is idempotent for buckets you
    // own (returns 200 if it already exists). This avoids a separate HeadBucket
    // round-trip which has proven unreliable via extism's HTTP host function.
    create_bucket(full_bucket, &cfg.region, creds).or_else(|e| {
        // BucketAlreadyOwnedByYou means it exists and we own it — not an error.
        if e.contains("BucketAlreadyOwnedByYou") || e.contains("BucketAlreadyExists") {
            log!(LogLevel::Info, "deckwatch-plugin-aws: S3 bucket {full_bucket} already exists");
            Ok(())
        } else {
            Err(e)
        }
    })?;

    log!(LogLevel::Info, "deckwatch-plugin-aws: S3 bucket {full_bucket} ready");

    if cfg.versioning {
        if let Err(e) = put_bucket_versioning(full_bucket, &cfg.region, creds) {
            log!(LogLevel::Warn, "deckwatch-plugin-aws: put_bucket_versioning: {e}");
        }
    }
    if cfg.public_access_block {
        if let Err(e) = put_public_access_block(full_bucket, &cfg.region, creds) {
            log!(LogLevel::Warn, "deckwatch-plugin-aws: put_public_access_block: {e}");
        }
    }
    if let Some(days) = cfg.lifecycle_days {
        if let Err(e) = put_bucket_lifecycle(full_bucket, &cfg.region, days, creds) {
            log!(LogLevel::Warn, "deckwatch-plugin-aws: put_bucket_lifecycle: {e}");
        }
    }
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Check whether a bucket exists. Returns `true` on 200/301/403, `false` on 404.
fn head_bucket(bucket: &str, region: &str, creds: &AwsCredentials) -> Result<bool, String> {
    // Use virtual-hosted-style: {bucket}.s3.{region}.amazonaws.com
    // Path-style (s3.{region}.amazonaws.com/{bucket}) returns 400 in some regions.
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let path = "/";
    let datetime = aws_sign::utc_now_iso8601(region);

    let (auth, payload_hash) = aws_sign::authorization_header(
        "HEAD",
        &host,
        path,
        "",
        "",
        &datetime,
        region,
        "s3",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        None,
    );

    let url = format!("https://{host}{path}");
    let mut req = HttpRequest::new(&url)
        .with_method("HEAD")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, None::<String>)
        .map_err(|e| format!("S3 HeadBucket HTTP error: {e}"))?;

    let status = resp.status_code();
    match status {
        // 200 — exists and owned; 301 — exists in another region; 403 — exists
        // but access denied (bucket name is taken).
        200 | 301 | 403 => Ok(true),
        404 => Ok(false),
        _ => {
            let body = String::from_utf8_lossy(&resp.body()).to_string();
            // Log all response headers for debugging
            let headers_debug: Vec<String> = resp.headers().iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            Err(format!(
                "S3 HeadBucket status={status} | url={url} | datetime={datetime} | resp_headers=[{}] | body={body}",
                headers_debug.join(",")
            ))
        }
    }
}

/// Create the bucket. `us-east-1` buckets must not send a
/// `CreateBucketConfiguration` body — all other regions require it.
fn create_bucket(bucket: &str, region: &str, creds: &AwsCredentials) -> Result<(), String> {
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let path = "/";
    let datetime = aws_sign::utc_now_iso8601(region);

    let (body, content_type) = if region == "us-east-1" {
        (String::new(), None)
    } else {
        let xml = format!(
            r#"<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>{region}</LocationConstraint></CreateBucketConfiguration>"#
        );
        (xml, Some("application/xml"))
    };

    let (auth, payload_hash) = aws_sign::authorization_header(
        "PUT",
        &host,
        &path,
        "",
        &body,
        &datetime,
        region,
        "s3",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        content_type,
    );

    let url = format!("https://{host}{path}");
    let mut req = HttpRequest::new(&url)
        .with_method("PUT")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ct) = content_type {
        req = req.with_header("Content-Type", ct);
    }
    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp =
        http::request(&req, Some(body)).map_err(|e| format!("S3 CreateBucket HTTP error: {e}"))?;

    let status = resp.status_code();
    if status >= 400 {
        let text = String::from_utf8_lossy(&resp.body()).to_string();
        let msg = extract_tag(&text, "Message").unwrap_or(text);
        return Err(format!("S3 CreateBucket error {status}: {msg}"));
    }

    Ok(())
}

fn put_bucket_versioning(bucket: &str, region: &str, creds: &AwsCredentials) -> Result<(), String> {
    let body = r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#;
    s3_put(
        bucket,
        region,
        "versioning",
        body,
        creds,
        "PutBucketVersioning",
    )
}

fn put_public_access_block(
    bucket: &str,
    region: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let body = r#"<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"#;
    s3_put(
        bucket,
        region,
        "publicAccessBlock",
        body,
        creds,
        "PutPublicAccessBlock",
    )
}

fn put_bucket_lifecycle(
    bucket: &str,
    region: &str,
    days: u32,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let body = format!(
        r#"<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>deckwatch-expire</ID><Status>Enabled</Status><Filter></Filter><Expiration><Days>{days}</Days></Expiration></Rule></LifecycleConfiguration>"#
    );
    s3_put(
        bucket,
        region,
        "lifecycle",
        &body,
        creds,
        "PutBucketLifecycleConfiguration",
    )
}

fn s3_put(
    bucket: &str,
    region: &str,
    sub_resource: &str,
    body: &str,
    creds: &AwsCredentials,
    op: &str,
) -> Result<(), String> {
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let path = "/";
    let datetime = aws_sign::utc_now_iso8601(region);

    let (auth, payload_hash) = aws_sign::authorization_header(
        "PUT",
        &host,
        path,
        sub_resource,
        body,
        &datetime,
        region,
        "s3",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/xml"),
    );

    let url = format!("https://{host}{path}?{sub_resource}");
    let mut req = HttpRequest::new(&url)
        .with_method("PUT")
        .with_header("Content-Type", "application/xml")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request(&req, Some(body.to_string()))
        .map_err(|e| format!("S3 {op} HTTP error: {e}"))?;

    let status = resp.status_code();
    if status >= 400 {
        let text = String::from_utf8_lossy(&resp.body()).to_string();
        let msg = extract_tag(&text, "Message").unwrap_or(text);
        return Err(format!("S3 {op} error {status}: {msg}"));
    }

    Ok(())
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml[start..start + end].trim().to_string())
}
