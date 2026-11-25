//! S3 bucket provisioning via the AWS S3 REST API.
//!
//! Uses virtual-hosted-style endpoints (`{bucket}.s3.{region}.amazonaws.com`)
//! and includes `x-amz-content-sha256` in all signed requests — both required
//! by S3 GovCloud. HeadBucket fails through extism's HTTP sandbox, so
//! `GetBucketTagging` is the existence check, and CreateBucket (idempotent for
//! owned buckets) runs only when that read can't confirm the bucket.

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials, S3Config};

// ── Public API ────────────────────────────────────────────────────────────────

/// What a `GetBucketTagging` read says about a bucket.
enum TagRead {
    /// The bucket exists and we can read it; these are its tags.
    Tags(crate::Tags),
    /// The read was denied (no `s3:GetBucketTagging`).
    Denied(String),
    /// Anything else: the bucket may not exist, so fall back to CreateBucket.
    Unknown,
}

fn read_bucket_tags(bucket: &str, region: &str, creds: &AwsCredentials) -> TagRead {
    match s3_get(bucket, region, "tagging", creds, "GetBucketTagging") {
        Ok(xml) => TagRead::Tags(crate::parse_s3_tag_set(&xml)),
        Err(e) if e.contains("NoSuchTagSet") => TagRead::Tags(vec![]),
        Err(e) if e.contains("AccessDenied") => TagRead::Denied(e),
        Err(_) => TagRead::Unknown,
    }
}

/// Ensure the S3 bucket exists and has the configured settings and tags.
///
/// deckwatch can reconcile every few seconds, so every step reads first and
/// writes only when something differs:
/// - `GetBucketTagging` doubles as the existence check (HeadBucket doesn't
///   work through extism's HTTP host function). It succeeds, or fails with
///   `NoSuchTagSet`, only for an existing bucket we can read. Otherwise
///   `CreateBucket` runs as before.
/// - Versioning, public access block and lifecycle are read before writing.
///   A failed read, e.g. a missing optional `s3:Get*` permission, means write
///   as before.
pub fn ensure_bucket(
    cfg: &S3Config,
    full_bucket: &str,
    tags: &[(String, String)],
    creds: &AwsCredentials,
) -> Result<(), String> {
    let tag_read = read_bucket_tags(full_bucket, &cfg.region, creds);

    if !matches!(tag_read, TagRead::Tags(_)) {
        // CreateBucket is idempotent for buckets we own, so it's safe when we
        // couldn't tell whether the bucket exists.
        create_bucket(full_bucket, &cfg.region, creds).or_else(|e| {
            // 409 BucketAlreadyOwnedByYou means we own the bucket — not an error.
            // Error string format: "S3 CreateBucket error 409 [BucketAlreadyOwnedByYou]: ..."
            if e.contains("BucketAlreadyOwnedByYou")
                || e.contains("BucketAlreadyExists")
                || e.contains("you already own it")
            {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    }

    let region = &cfg.region;
    if cfg.versioning
        && !s3_get(
            full_bucket,
            region,
            "versioning",
            creds,
            "GetBucketVersioning",
        )
        .is_ok_and(|xml| crate::s3_versioning_enabled(&xml))
    {
        if let Err(e) = put_bucket_versioning(full_bucket, region, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: put_bucket_versioning: {e}"
            );
        }
    }
    if cfg.public_access_block
        && !s3_get(
            full_bucket,
            region,
            "publicAccessBlock",
            creds,
            "GetPublicAccessBlock",
        )
        .is_ok_and(|xml| crate::s3_public_access_fully_blocked(&xml))
    {
        if let Err(e) = put_public_access_block(full_bucket, region, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: put_public_access_block: {e}"
            );
        }
    }
    if let Some(days) = cfg.lifecycle_days {
        let current = s3_get(
            full_bucket,
            region,
            "lifecycle",
            creds,
            "GetBucketLifecycleConfiguration",
        );
        if !current.is_ok_and(|xml| crate::s3_lifecycle_has_expiry_rule(&xml, days)) {
            if let Err(e) = put_bucket_lifecycle(full_bucket, region, days, creds) {
                log!(
                    LogLevel::Warn,
                    "deckwatch-plugin-aws: put_bucket_lifecycle: {e}"
                );
            }
        }
    }
    if !tags.is_empty() {
        if let Err(e) = apply_bucket_tags(full_bucket, region, tags, tag_read, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: bucket tagging for {full_bucket}: {e}"
            );
        }
    }
    Ok(())
}

/// Whether a bucket we can read exists, for `RESOURCE_NAME_PREFIX` name
/// resolution. HeadBucket doesn't work through extism's HTTP host function, so
/// this reads the bucket's tags: success or `NoSuchTagSet` means it exists,
/// `NoSuchBucket` means it doesn't, and anything else (e.g. 403 for another
/// account's bucket) is an error, which callers treat as "doesn't exist".
pub fn bucket_exists(bucket: &str, region: &str, creds: &AwsCredentials) -> Result<bool, String> {
    match s3_get(bucket, region, "tagging", creds, "GetBucketTagging") {
        Ok(_) => Ok(true),
        Err(e) if e.contains("NoSuchTagSet") => Ok(true),
        Err(e) if e.contains("NoSuchBucket") => Ok(false),
        Err(e) => Err(e),
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Merge the plugin's tags into the bucket's existing tag set.
///
/// PutBucketTagging replaces the whole set, so read it first and keep tags
/// set by anyone else. The write is skipped when the bucket already has every
/// tag. `tag_read` is the read `ensure_bucket` already made; if it didn't
/// return tags (the bucket was just created), the tags are read again.
fn apply_bucket_tags(
    bucket: &str,
    region: &str,
    tags: &[(String, String)],
    tag_read: TagRead,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let existing = match tag_read {
        TagRead::Tags(existing) => existing,
        // Reading again would be denied again.
        TagRead::Denied(e) => return Err(e),
        // Same handling as before this read was shared: any error other than
        // NoSuchTagSet means we can't merge safely, so don't write.
        TagRead::Unknown => match s3_get(bucket, region, "tagging", creds, "GetBucketTagging") {
            Ok(xml) => crate::parse_s3_tag_set(&xml),
            Err(e) if e.contains("NoSuchTagSet") => vec![],
            Err(e) => return Err(e),
        },
    };
    if crate::tags_satisfied(&existing, tags) {
        return Ok(());
    }
    let merged = crate::merge_tags(&existing, tags);
    s3_put(
        bucket,
        region,
        "tagging",
        &crate::s3_tagging_xml(&merged),
        creds,
        "PutBucketTagging",
    )
}

/// GET a bucket sub-resource (e.g. `tagging`) and return the response body.
fn s3_get(
    bucket: &str,
    region: &str,
    sub_resource: &str,
    creds: &AwsCredentials,
    op: &str,
) -> Result<String, String> {
    let (ep, path) = s3_target(bucket, region)?;
    let host = ep.host.clone();
    let path = path.as_str();
    let datetime = aws_sign::utc_now_iso8601(region);

    let (auth, payload_hash) = aws_sign::authorization_header(
        "GET",
        &host,
        path,
        sub_resource,
        "",
        &datetime,
        region,
        "s3",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        None,
    );

    let url = format!("{}{path}?{sub_resource}", ep.base_url);
    let mut req = HttpRequest::new(&url)
        .with_method("GET")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);
    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp =
        http::request::<String>(&req, None).map_err(|e| format!("S3 {op} HTTP error: {e}"))?;
    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();
    if status >= 400 {
        let code = extract_tag(&text, "Code").unwrap_or_default();
        let msg = extract_tag(&text, "Message").unwrap_or_else(|| text.clone());
        return Err(format!("S3 {op} error {status} [{code}]: {msg}"));
    }
    Ok(text)
}

/// Endpoint and canonical path for a bucket-level request.
///
/// Real AWS uses virtual-hosted style (`<bucket>.s3.<region>.amazonaws.com`,
/// path `/`), which GovCloud requires. Under `AWS_ENDPOINT_URL` the request
/// goes path-style (`<endpoint>/<bucket>`) because emulators cannot serve
/// per-bucket virtual hosts.
fn s3_target(bucket: &str, region: &str) -> Result<(crate::Endpoint, String), String> {
    let ep = crate::service_endpoint(&format!("{bucket}.s3.{region}.amazonaws.com"))?;
    let path = if ep.overridden {
        format!("/{bucket}")
    } else {
        "/".to_string()
    };
    Ok((ep, path))
}

/// Create the bucket using virtual-hosted-style addressing.
/// `us-east-1` must not send a `CreateBucketConfiguration` body.
fn create_bucket(bucket: &str, region: &str, creds: &AwsCredentials) -> Result<(), String> {
    let (ep, path) = s3_target(bucket, region)?;
    let host = ep.host.clone();
    let path = path.as_str();
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

    let url = format!("{}{path}", ep.base_url);
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
        let code = extract_tag(&text, "Code").unwrap_or_default();
        let msg = extract_tag(&text, "Message").unwrap_or_else(|| text.clone());
        return Err(format!("S3 CreateBucket error {status} [{code}]: {msg}"));
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
    // The rule ID must match what s3_lifecycle_has_expiry_rule() looks for.
    let id = crate::S3_LIFECYCLE_RULE_ID;
    let body = format!(
        r#"<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>{id}</ID><Status>Enabled</Status><Filter></Filter><Expiration><Days>{days}</Days></Expiration></Rule></LifecycleConfiguration>"#
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
    let (ep, path) = s3_target(bucket, region)?;
    let host = ep.host.clone();
    let path = path.as_str();
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

    let url = format!("{}{path}?{sub_resource}", ep.base_url);
    // S3 requires a message integrity header on bucket-configuration PUTs
    // (tagging, lifecycle); Content-MD5 isn't x-amz-*, so it needn't be signed.
    let mut req = HttpRequest::new(&url)
        .with_method("PUT")
        .with_header("Content-MD5", crate::content_md5(body))
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
