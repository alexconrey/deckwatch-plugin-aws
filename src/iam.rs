//! IAM role management via the AWS IAM Query API.
//!
//! IAM is a global service with a single endpoint (`iam.amazonaws.com`). Its
//! query API uses the same POST form-encoded body pattern as RDS; the Sig V4
//! region is always `"us-east-1"` regardless of where the workload runs.
//!
//! ## Trust policy
//!
//! The role is created with a wildcard EKS trust policy so it can be assumed
//! immediately. Operators should tighten this by setting their OIDC provider ARN:
//!
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [{
//!     "Effect": "Allow",
//!     "Principal": {"Federated": "arn:aws:iam::<account>:oidc-provider/<oidc-url>"},
//!     "Action": "sts:AssumeRoleWithWebIdentity",
//!     "Condition": {"StringEquals": {"<oidc-url>:sub": "system:serviceaccount:<ns>:<sa>"}}
//!   }]
//! }
//! ```

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials};

// IAM is a global service — always use us-east-1 for Sig V4.
const IAM_REGION: &str = "us-east-1";
const IAM_HOST: &str = "iam.amazonaws.com";

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure a role with the given name exists. Creates it if it does not.
///
/// Returns the role ARN on success.
pub fn ensure_role(role_name: &str, creds: &AwsCredentials) -> Result<String, String> {
    // Check if the role already exists.
    if let Some(arn) = get_role(role_name, creds)? {
        log!(
            LogLevel::Info,
            "deckwatch-plugin-aws: IAM role {role_name} already exists"
        );
        return Ok(arn);
    }

    // Create with a broad EKS trust policy. Operators should narrow this.
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}"#;

    let body = format!(
        "Action=CreateRole&Version=2010-05-08&RoleName={}&AssumeRolePolicyDocument={}",
        url_encode(role_name),
        url_encode(trust),
    );
    let xml = iam_query(&body, creds)?;

    extract_tag(&xml, "Arn").ok_or_else(|| format!("CreateRole: could not parse ARN from response"))
}

/// Attach an inline policy granting `rds-db:connect` for the instance.
///
/// Using an inline (embedded) policy avoids the 10-managed-policy limit per role
/// and keeps the policy lifecycle tied to the role.
pub fn attach_rds_policy(
    role_name: &str,
    rds_identifier: &str,
    region: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:{region}:*:dbuser/{rds_identifier}/*"}}]}}"#
    );
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName=deckwatch-rds-connect&PolicyDocument={}",
        url_encode(role_name),
        url_encode(&policy),
    );
    let _xml = iam_query(&body, creds)?;
    Ok(())
}

/// Attach an inline policy granting standard S3 object operations on the bucket.
pub fn attach_s3_policy(
    role_name: &str,
    bucket_name: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::{bucket_name}/*"}},{{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::{bucket_name}"}}]}}"#
    );
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName=deckwatch-s3-access&PolicyDocument={}",
        url_encode(role_name),
        url_encode(&policy),
    );
    let _xml = iam_query(&body, creds)?;
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Call `GetRole` and return the ARN if found, `None` if the role does not exist.
fn get_role(role_name: &str, creds: &AwsCredentials) -> Result<Option<String>, String> {
    let body = format!(
        "Action=GetRole&Version=2010-05-08&RoleName={}",
        url_encode(role_name)
    );
    let xml = iam_query(&body, creds)?;

    if xml.contains("NoSuchEntity") {
        return Ok(None);
    }

    Ok(extract_tag(&xml, "Arn"))
}

fn iam_query(body: &str, creds: &AwsCredentials) -> Result<String, String> {
    let datetime = aws_sign::utc_now_iso8601();
    let auth = aws_sign::authorization_header(
        "POST",
        IAM_HOST,
        "/",
        "",
        body,
        &datetime,
        IAM_REGION,
        "iam",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/x-www-form-urlencoded"),
    );

    let url = format!("https://{IAM_HOST}/");
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Host", IAM_HOST)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, Some(body.to_string()))
        .map_err(|e| format!("IAM API HTTP error: {e}"))?;

    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();

    if status >= 400 {
        let msg = extract_tag(&text, "Message")
            .or_else(|| extract_tag(&text, "message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("IAM API error {status}: {msg}"));
    }

    Ok(text)
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml[start..start + end].trim().to_string())
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
