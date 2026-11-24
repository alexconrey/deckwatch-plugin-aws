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

/// Returns `(endpoint, iam_signing_region)` for the given workload region.
///
/// Precedence: `IAM_ENDPOINT` (hostname, HTTPS) → `AWS_ENDPOINT_URL` →
/// the partition's global IAM endpoint.
fn iam_endpoint(region: &str) -> Result<(crate::Endpoint, String), String> {
    let endpoint = match config::get("IAM_ENDPOINT")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
    {
        Some(host) => crate::Endpoint {
            base_url: format!("https://{host}"),
            host,
            overridden: true,
        },
        None => crate::service_endpoint(if region.starts_with("us-gov-") {
            "iam.us-gov.amazonaws.com"
        } else {
            "iam.amazonaws.com"
        })?,
    };

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

    Ok((endpoint, signing_region))
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
                .next_back()
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
    let partition = crate::aws_partition(region);
    let account = config::get("AWS_ROLE_ARN")
        .ok()
        .flatten()
        .and_then(|arn| arn.split(':').nth(4).map(|s| s.to_string()))
        .unwrap_or_else(|| "*".to_string());
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:{partition}:rds-db:{region}:{account}:dbuser:{rds_resource_id}/{db_user}"}}]}}"#
    );
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}&PolicyDocument={}",
        url_encode(role_name),
        crate::POLICY_RDS,
        url_encode(&policy),
    );
    let _xml = iam_query(&body, creds)?;
    Ok(())
}

/// Attach an inline policy granting standard S3 object operations on the bucket.
///
/// `region` is the bucket's region; it selects the ARN partition so GovCloud
/// buckets get `arn:aws-us-gov:s3:::` resources rather than `arn:aws:s3:::`.
pub fn attach_s3_policy(
    role_name: &str,
    bucket_name: &str,
    region: &str,
    creds: &AwsCredentials,
) -> Result<(), String> {
    let policy = crate::s3_access_policy_document(bucket_name, region);
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}&PolicyDocument={}",
        url_encode(role_name),
        crate::POLICY_S3,
        url_encode(&policy),
    );
    iam_query(&body, creds)?;
    Ok(())
}

/// Attach an inline policy granting ECR image pull operations.
pub fn attach_ecr_policy(role_name: &str, creds: &AwsCredentials) -> Result<(), String> {
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken"],"Resource":"*"},{"Effect":"Allow","Action":["ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"],"Resource":"*"}]}"#;
    let body = format!(
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}&PolicyDocument={}",
        url_encode(role_name),
        crate::POLICY_ECR,
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
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}&PolicyDocument={}",
        url_encode(role_name),
        crate::POLICY_SQS,
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
        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}&PolicyDocument={}",
        url_encode(role_name),
        crate::POLICY_SECRETS,
        url_encode(&policy),
    );
    iam_query(&body, creds)?;
    Ok(())
}

// ── Cleanup (deprovision) ─────────────────────────────────────────────────────

/// Delete one inline policy from a role. Returns `false` if the role or policy
/// doesn't exist, so cleanup is idempotent.
pub fn delete_role_policy(
    role_name: &str,
    policy_name: &str,
    creds: &AwsCredentials,
) -> Result<bool, String> {
    let body = format!(
        "Action=DeleteRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}",
        url_encode(role_name),
        url_encode(policy_name),
    );
    match iam_query(&body, creds) {
        Ok(_) => Ok(true),
        Err(e) if e.contains("NoSuchEntity") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Names of a role's inline policies, or `None` if the role doesn't exist.
pub fn list_role_policies(
    role_name: &str,
    creds: &AwsCredentials,
) -> Result<Option<Vec<String>>, String> {
    let body = format!(
        "Action=ListRolePolicies&Version=2010-05-08&RoleName={}&MaxItems=1000",
        url_encode(role_name)
    );
    match iam_query(&body, creds) {
        Ok(xml) => Ok(Some(crate::xml_tag_values(&xml, "member"))),
        Err(e) if e.contains("NoSuchEntity") => Ok(None),
        Err(e) => Err(e),
    }
}

/// ARNs of the managed policies attached to a role (empty if the role is gone).
pub fn list_attached_role_policy_arns(
    role_name: &str,
    creds: &AwsCredentials,
) -> Result<Vec<String>, String> {
    let body = format!(
        "Action=ListAttachedRolePolicies&Version=2010-05-08&RoleName={}&MaxItems=1000",
        url_encode(role_name)
    );
    match iam_query(&body, creds) {
        Ok(xml) => Ok(crate::xml_tag_values(&xml, "PolicyArn")),
        Err(e) if e.contains("NoSuchEntity") => Ok(vec![]),
        Err(e) => Err(e),
    }
}

/// Delete a role. It must have no policies left. Returns `false` if it was
/// already gone.
pub fn delete_role(role_name: &str, creds: &AwsCredentials) -> Result<bool, String> {
    let body = format!(
        "Action=DeleteRole&Version=2010-05-08&RoleName={}",
        url_encode(role_name)
    );
    match iam_query(&body, creds) {
        Ok(_) => Ok(true),
        Err(e) if e.contains("NoSuchEntity") => Ok(false),
        Err(e) => Err(e),
    }
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
    // A missing role comes back as HTTP 404 with Code=NoSuchEntity, which
    // iam_query surfaces as Err — map it to Ok(None) so ensure_role creates it.
    match iam_query(&body, creds) {
        Ok(xml) => Ok(extract_tag(&xml, "Arn")),
        Err(e) if e.contains("NoSuchEntity") => Ok(None),
        Err(e) => Err(e),
    }
}

fn iam_query(body: &str, creds: &AwsCredentials) -> Result<String, String> {
    let (ep, iam_region) = iam_endpoint(&creds.region)?;
    let iam_host = ep.host.clone();
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

    let url = format!("{}/", ep.base_url);
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
        let code = extract_tag(&text, "Code").unwrap_or_default();
        let msg = extract_tag(&text, "Message")
            .or_else(|| extract_tag(&text, "message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("IAM API error {status} {code}: {msg}"));
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
