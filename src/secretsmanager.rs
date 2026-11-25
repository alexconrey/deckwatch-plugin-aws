//! Secrets Manager secret provisioning via the AWS JSON API.
//!
//! Secrets Manager uses a JSON API at `secretsmanager.<region>.amazonaws.com`
//! with `X-Amz-Target` headers (similar to DynamoDB).
//!
//! Sig V4 service name: `"secretsmanager"`.
//! Content-Type: `application/x-amz-json-1.1`.
//!
//! ## Idempotency
//!
//! `ensure_secret` calls `DescribeSecret` before `CreateSecret`. The secret
//! stores no value on creation — it is an empty container that the application
//! (or an operator) populates. Applications read the value via the IAM policy
//! granted by `iam::attach_secretsmanager_policy`.

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials};

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure a Secrets Manager secret exists, creating it (empty) if it does not.
///
/// Returns the secret ARN. The secret is created without a value — the
/// application or an operator is responsible for populating it.
pub fn ensure_secret(
    secret_name: &str,
    description: &str,
    tags: &[(String, String)],
    creds: &AwsCredentials,
) -> Result<String, String> {
    if let Some((arn, existing_tags)) = describe_secret(secret_name, creds)? {
        // TagResource adds or updates only these keys; other tags are kept.
        // Skipped when DescribeSecret already shows every tag.
        if !crate::tags_satisfied(&existing_tags, tags) {
            let body = serde_json::json!({ "SecretId": arn, "Tags": crate::json_tag_list(tags) })
                .to_string();
            if let Err(e) = sm_call("secretsmanager.TagResource", &body, creds) {
                log!(
                    LogLevel::Warn,
                    "deckwatch-plugin-aws: TagResource for secret '{secret_name}': {e}"
                );
            }
        }
        return Ok(arn);
    }

    create_secret(secret_name, description, tags, creds)
}

/// Schedule a secret for deletion with a recovery window.
///
/// Returns the deletion date string from AWS (`DeletionDate`).
/// The secret can be restored from the AWS console within `recovery_window_days` (7–30).
pub fn schedule_delete_secret(
    secret_name: &str,
    recovery_window_days: u32,
    creds: &AwsCredentials,
) -> Result<String, String> {
    let body = serde_json::json!({
        "SecretId": secret_name,
        "RecoveryWindowInDays": recovery_window_days,
    })
    .to_string();
    let json = sm_call("secretsmanager.DeleteSecret", &body, creds)?;
    let deletion_date =
        crate::json_str_field(&json, "DeletionDate").unwrap_or_else(|| "unknown".into());
    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: secret '{secret_name}' scheduled for deletion on {deletion_date}"
    );
    Ok(deletion_date)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// The secret's ARN and tags, or `None` if it doesn't exist.
fn describe_secret(
    secret_name: &str,
    creds: &AwsCredentials,
) -> Result<Option<(String, crate::Tags)>, String> {
    let body = serde_json::json!({ "SecretId": secret_name }).to_string();

    match sm_call("secretsmanager.DescribeSecret", &body, creds) {
        // The ARN field is named "ARN" in the response.
        Ok(json) => {
            Ok(crate::json_str_field(&json, "ARN").map(|arn| (arn, crate::secret_tags(&json))))
        }
        Err(e) if e.contains("ResourceNotFoundException") => Ok(None),
        Err(e) => Err(e),
    }
}

fn create_secret(
    secret_name: &str,
    description: &str,
    tags: &[(String, String)],
    creds: &AwsCredentials,
) -> Result<String, String> {
    // Built with serde so names and descriptions are JSON-escaped.
    let mut request = serde_json::json!({ "Name": secret_name, "Description": description });
    if !tags.is_empty() {
        request["Tags"] = crate::json_tag_list(tags);
    }
    let body = request.to_string();
    let json = sm_call("secretsmanager.CreateSecret", &body, creds)?;

    crate::json_str_field(&json, "ARN").ok_or_else(|| {
        format!("Secrets Manager CreateSecret: could not parse ARN from response: {json}")
    })
}

/// POST to the Secrets Manager JSON API with the given target and body.
fn sm_call(target: &str, body: &str, creds: &AwsCredentials) -> Result<String, String> {
    let ep = crate::service_endpoint(&format!("secretsmanager.{}.amazonaws.com", creds.region))?;
    let host = ep.host.clone();
    let datetime = aws_sign::utc_now_iso8601(&creds.region);
    let (auth, payload_hash) = aws_sign::authorization_header(
        "POST",
        &host,
        "/",
        "",
        body,
        &datetime,
        &creds.region,
        "secretsmanager",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/x-amz-json-1.1"),
    );

    let url = format!("{}/", ep.base_url);
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-amz-json-1.1")
        .with_header("X-Amz-Target", target)
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, Some(body.to_string()))
        .map_err(|e| format!("Secrets Manager HTTP error: {e}"))?;

    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();

    if status >= 400 {
        return Err(format!("Secrets Manager error {status}: {text}"));
    }

    Ok(text)
}
