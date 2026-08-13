//! IAM role management via the AWS IAM Query API.
//!
//! IAM endpoint and Sig V4 signing region are partition-aware:
//! - Commercial:  `iam.amazonaws.com`,        signing region `us-east-1`
//! - GovCloud:    `iam.us-gov.amazonaws.com`, signing region `us-gov-west-1`
//!
//! ## Trust policy
//!
//! When `OIDC_PROVIDER_ARN` is configured in the plugin config, `ensure_role`
//! generates a proper IRSA trust policy scoped to the workload's service account:
//!
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [{
//!     "Effect": "Allow",
//!     "Principal": {"Federated": "arn:aws:iam::<account>:oidc-provider/<url>"},
//!     "Action": "sts:AssumeRoleWithWebIdentity",
//!     "Condition": {
//!       "StringEquals": {
//!         "<oidc-url>:sub": "system:serviceaccount:<ns>:<sa>",
//!         "<oidc-url>:aud": "sts.amazonaws.com"
//!       }
//!     }
//!   }]
//! }
//! ```
//!
//! `UpdateAssumeRolePolicy` is called on every reconcile so that adding
//! `OIDC_PROVIDER_ARN` after initial role creation takes effect automatically.

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials};

/// Returns `(iam_host, iam_signing_region)` for the given workload region.
fn iam_endpoint(region: &str) -> (String, String) {
    let host = config::get("IAM_ENDPOINT")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if region.starts_with("us-gov-") {
                "iam.us-gov.amazonaws.com".to_string()
            } else {
                "iam.amazonaws.com".to_string()
            }
        });

    let signing_region = config::get("IAM_SIGNING_REGION")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if region.starts_with("us-gov-") {
                "us-gov-west-1".to_string()
            } else {
                "us-east-1".to_string()
            }
        });

    (host, signing_region)
}

// ── Trust policy builder ──────────────────────────────────────────────────────

fn trust_policy_document(namespace: &str, sa_name: &str) -> String {
    let oidc_arn = config::get("OIDC_PROVIDER_ARN")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty());

    match oidc_arn {
        Some(arn) => {
            // ARN format: arn:aws[-partition]:iam::<account>:oidc-provider/<url>
            let oidc_url = arn
                .split(':')
                .last()
                .unwrap_or("")
                .trim_start_matches("oidc-provider/");
            format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{arn}"}},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{{"StringEquals":{{"{oidc_url}:sub":"system:serviceaccount:{namespace}:{sa_name}","{oidc_url}:aud":"sts.amazonaws.com"}}}}}}]}}"#
            )
        }
        None => {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: OIDC_PROVIDER_ARN not configured — \
                 workload IAM role will have no trust principals and IRSA will not work."
            );
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string()
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure a role with the given name exists and has the correct trust policy.
///
/// Creates the role if it does not exist; calls `UpdateAssumeRolePolicy` on
/// every reconcile so OIDC_PROVIDER_ARN changes take effect automatically.
///
/// Returns the role ARN on success.
pub fn ensure_role(
    role_name: &str,
    namespace: &str,
    sa_name: &str,
    creds: &AwsCredentials,
) -> Result<String, String> {
    let trust = trust_policy_document(namespace, sa_name);

    if let Some(arn) = get_role(role_name, creds)? {
        log!(
            LogLevel::Info,
            "deckwatch-plugin-aws: IAM role {role_name} already exists"
        );
        if let Err(e) = update_assume_role_policy(role_name, &trust, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: UpdateAssumeRolePolicy for {role_name}: {e}"
            );
        }
        return Ok(arn);
    }

    let role_path = config::get("ROLE_PATH")
        .ok()
        .flatten()
        .filter(|p| p.starts_with('/') && p.ends_with('/'))
        .unwrap_or_else(|| "/deckwatch-plugin/".to_string());

    let body = format!(
        "Action=CreateRole&Version=2010-05-08&Path={}&RoleName={}&AssumeRolePolicyDocument={}",
        url_encode(&role_path),
        url_encode(role_name),
        url_encode(&trust),
    );
    let xml = iam_query(&body, creds)?;

    extract_tag(&xml, "Arn")
        .ok_or_else(|| "CreateRole: could not parse ARN from response".to_string())
}

/// Attach an inline policy granting `rds-db:connect` for the instance.
///
/// Using an inline (embedded) policy avoids the 10-managed-policy limit per role
/// and keeps the policy lifecycle tied to the role.
/// `rds_resource_id` is the `DbiResourceId` (e.g. `db-CO2YWIF6C7KV5K3DJQ4IEBP7II`),
/// not the instance identifier. `db_user` is the PostgreSQL username that has
/// `rds_iam` granted. The partition is derived from the region.
pub fn attach_rds_policy(
    role_name: &str,
    rds_resource_id: &str,
    db_user: &str,
    region: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let partition = if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else if region.starts_with("cn-") {
        "aws-cn"
    } else {
        "aws"
    };
    let account = config::get("AWS_ROLE_ARN")
        .ok()
        .flatten()
        .and_then(|arn| arn.split(':').nth(4).map(|s| s.to_string()))
        .unwrap_or_else(|| "*".to_string());
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:{partition}:rds-db:{region}:{account}:dbuser:{rds_resource_id}/{db_user}"}}]}}"#
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
    iam_query(&body, creds)?;
    Ok(())
}

/// Attach an inline policy granting ECR image pull operations.
pub fn attach_ecr_policy(role_name: &str, creds: &AwsCredentials) -> Result<(), String> {
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken"],"Resource":"*"},{"Effect":"Allow","Action":["ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"],"Resource":"*"}]}"#;
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName=deckwatch-ecr-pull&PolicyDocument={}",
        url_encode(role_name),
        url_encode(policy),
    );
    iam_query(&body, creds)?;
    Ok(())
}

/// Attach an inline policy granting standard SQS producer/consumer operations.
pub fn attach_sqs_policy(
    role_name: &str,
    queue_arn: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueUrl","sqs:GetQueueAttributes","sqs:ChangeMessageVisibility"],"Resource":"{queue_arn}"}}]}}"#
    );
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName=deckwatch-sqs-access&PolicyDocument={}",
        url_encode(role_name),
        url_encode(&policy),
    );
    iam_query(&body, creds)?;
    Ok(())
}

/// Attach an inline policy granting `secretsmanager:GetSecretValue` on the given secret ARNs.
pub fn attach_secretsmanager_policy(
    role_name: &str,
    secret_arns: &[String],
    creds: &AwsCredentials,
) -> Result<(), String> {
    if secret_arns.is_empty() {
        return Ok(());
    }
    let arns_json: String = secret_arns
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(",");
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Resource":[{arns_json}]}}]}}"#
    );
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName=deckwatch-secretsmanager-access&PolicyDocument={}",
        url_encode(role_name),
        url_encode(&policy),
    );
    iam_query(&body, creds)?;
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn update_assume_role_policy(
    role_name: &str,
    trust: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let body = format!(
        "Action=UpdateAssumeRolePolicy&Version=2010-05-08&RoleName={}&PolicyDocument={}",
        url_encode(role_name),
        url_encode(trust),
    );
    iam_query(&body, creds)?;
    Ok(())
}

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
    let (iam_host, iam_region) = iam_endpoint(&creds.region);
    let datetime = aws_sign::utc_now_iso8601(&creds.region);
    let (auth, payload_hash) = aws_sign::authorization_header(
        "POST",
        &iam_host,
        "/",
        "",
        body,
        &datetime,
        &iam_region,
        "iam",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/x-www-form-urlencoded"),
    );

    let url = format!("https://{iam_host}/");
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Host", &iam_host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
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
