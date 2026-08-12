//! S3 bucket provisioning via the AWS S3 REST API.
//!
//! Uses virtual-hosted-style endpoints (`{bucket}.s3.{region}.amazonaws.com`)
//! and includes `x-amz-content-sha256` in all signed requests — both required
//! by S3 GovCloud. CreateBucket is called directly (idempotent for owned buckets)
//! to avoid HeadBucket which fails via extism's HTTP sandbox.

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials, S3Config};

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure the S3 bucket exists, creating and configuring it if it does not.
pub fn ensure_bucket(
    cfg: &S3Config,
    full_bucket: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    // CreateBucket is idempotent for buckets we own — returns 200 if it
    // already exists, which is simpler than HeadBucket + conditional create.
    create_bucket(full_bucket, &cfg.region, creds).or_else(|e| {
        if e.contains("BucketAlreadyOwnedByYou") || e.contains("BucketAlreadyExists") {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: S3 bucket {full_bucket} already exists"
            );
            Ok(())
        } else {
            Err(e)
        }
    })?;

    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: S3 bucket {full_bucket} ready"
    );

    if cfg.versioning {
        if let Err(e) = put_bucket_versioning(full_bucket, &cfg.region, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: put_bucket_versioning: {e}"
            );
        }
    }
    if cfg.public_access_block {
        if let Err(e) = put_public_access_block(full_bucket, &cfg.region, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: put_public_access_block: {e}"
            );
        }
    }
    if let Some(days) = cfg.lifecycle_days {
        if let Err(e) = put_bucket_lifecycle(full_bucket, &cfg.region, days, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: put_bucket_lifecycle: {e}"
            );
        }
    }
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Create the bucket using virtual-hosted-style addressing.
/// `us-east-1` must not send a `CreateBucketConfiguration` body.
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
        path,
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
