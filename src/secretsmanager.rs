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
    creds: &AwsCredentials,
) -> Result<String, String> {
    if let Some(arn) = describe_secret(secret_name, creds)? {
        log!(
            LogLevel::Info,
            "deckwatch-plugin-aws: Secrets Manager secret '{secret_name}' already exists"
        );
        return Ok(arn);
    }

    create_secret(secret_name, description, creds)
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
    let body =
        format!(r#"{{"SecretId":"{secret_name}","RecoveryWindowInDays":{recovery_window_days}}}"#);
    let json = sm_call("secretsmanager.DeleteSecret", &body, creds)?;
    let deletion_date = extract_json_str(&json, "DeletionDate").unwrap_or_else(|| "unknown".into());
    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: secret '{secret_name}' scheduled for deletion on {deletion_date}"
    );
    Ok(deletion_date)
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn describe_secret(secret_name: &str, creds: &AwsCredentials) -> Result<Option<String>, String> {
    let body = format!(r#"{{"SecretId":"{secret_name}"}}"#);

    match sm_call("secretsmanager.DescribeSecret", &body, creds) {
        Ok(json) => {
            // The ARN field is named "ARN" in the response.
            let arn = extract_json_str(&json, "ARN");
            Ok(arn)
        }
        Err(e) if e.contains("ResourceNotFoundException") => Ok(None),
        Err(e) => Err(e),
    }
}

fn create_secret(
    secret_name: &str,
    description: &str,
    creds: &AwsCredentials,
) -> Result<String, String> {
    let body = format!(r#"{{"Name":"{secret_name}","Description":"{description}"}}"#);
    let json = sm_call("secretsmanager.CreateSecret", &body, creds)?;

    extract_json_str(&json, "ARN").ok_or_else(|| {
        format!("Secrets Manager CreateSecret: could not parse ARN from response: {json}")
    })
}

/// POST to the Secrets Manager JSON API with the given target and body.
fn sm_call(target: &str, body: &str, creds: &AwsCredentials) -> Result<String, String> {
    let host = format!("secretsmanager.{}.amazonaws.com", creds.region);
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

    let url = format!("https://{host}/");
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

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')?;
    Some(json[start..start + end].to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_arn_from_describe_response() {
        let json = r#"{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp-AbCdEf","Name":"myapp","VersionId":"xxx"}"#;
        assert_eq!(
            extract_json_str(json, "ARN"),
            Some("arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp-AbCdEf".to_string())
        );
    }

    #[test]
    fn extract_returns_none_for_missing_key() {
        let json = r#"{"Name":"myapp"}"#;
        assert_eq!(extract_json_str(json, "ARN"), None);
    }
}
