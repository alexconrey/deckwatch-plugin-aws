//! RDS instance provisioning via the AWS RDS Query API.
//!
//! The RDS Query API is a POST endpoint at `https://rds.<region>.amazonaws.com/`
//! with an `application/x-www-form-urlencoded` body. Responses are XML.
//!
//! Credentials and region come from the caller's [`AwsCredentials`].

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials, RdsConfig};

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure an RDS DB instance exists, creating it if it does not.
///
/// Returns the endpoint hostname. The endpoint may be empty if the instance was
/// just created and is not yet in the `available` state — callers should treat
/// an empty string as "provisioning in progress" and not block the deployment.
pub fn ensure_instance(cfg: &RdsConfig, creds: &AwsCredentials) -> Result<String, String> {
    match describe_db_instance(&cfg.identifier, creds)? {
        Some(info) => {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: RDS instance {} status={}",
                cfg.identifier,
                info.status
            );
            Ok(info.endpoint_address)
        }
        None => {
            create_db_instance(cfg, creds)?;
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: RDS instance {} creation initiated",
                cfg.identifier
            );
            // Endpoint not yet available — the next reconcile will fill it in.
            Ok(String::new())
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct DbInstanceInfo {
    status: String,
    endpoint_address: String,
}

fn describe_db_instance(
    identifier: &str,
    creds: &AwsCredentials,
) -> Result<Option<DbInstanceInfo>, String> {
    let body =
        format!("Action=DescribeDBInstances&Version=2014-10-31&DBInstanceIdentifier={identifier}");
    let xml = rds_query(&body, creds)?;

    if xml.contains("DBInstanceNotFound") {
        return Ok(None);
    }

    Ok(Some(DbInstanceInfo {
        status: extract_tag(&xml, "DBInstanceStatus").unwrap_or_default(),
        endpoint_address: extract_tag(&xml, "Address").unwrap_or_default(),
    }))
}

fn create_db_instance(cfg: &RdsConfig, creds: &AwsCredentials) -> Result<(), String> {
    let multi_az = cfg.multi_az.to_string();
    let iam_auth = cfg.iam_auth.to_string();

    let mut params: Vec<(&str, &str)> = vec![
        ("DBInstanceIdentifier", &cfg.identifier),
        ("DBInstanceClass", &cfg.instance_class),
        ("Engine", &cfg.engine),
        ("AllocatedStorage", &cfg.allocated_storage),
        ("DBName", &cfg.db_name),
        ("MultiAZ", &multi_az),
        ("EnableIAMDatabaseAuthentication", &iam_auth),
        ("MasterUsername", "admin"),
        // Delegate password management to AWS Secrets Manager so no plaintext
        // credential appears in the API call or plugin state.
        ("ManageMasterUserPassword", "true"),
        ("StorageEncrypted", "true"),
        ("StorageType", "gp3"),
        ("PubliclyAccessible", "false"),
        ("DeletionProtection", "true"),
    ];

    if let Some(ref sg) = cfg.subnet_group {
        params.push(("DBSubnetGroupName", sg));
    }

    // Build repeated VPC security group parameters.
    // Format: VpcSecurityGroupIds.member.N
    let sg_params: Vec<(String, String)> = cfg
        .security_groups
        .iter()
        .enumerate()
        .map(|(i, sg)| (format!("VpcSecurityGroupIds.member.{}", i + 1), sg.clone()))
        .collect();

    let mut body = "Action=CreateDBInstance&Version=2014-10-31".to_string();
    for (k, v) in &params {
        body.push('&');
        body.push_str(&url_encode(k));
        body.push('=');
        body.push_str(&url_encode(v));
    }
    for (k, v) in &sg_params {
        body.push('&');
        body.push_str(&url_encode(k));
        body.push('=');
        body.push_str(&url_encode(v));
    }

    let xml = rds_query(&body, creds)?;
    if xml.contains("Error") && !xml.contains("DBInstanceIdentifier") {
        let msg = extract_tag(&xml, "Message").unwrap_or_else(|| xml.clone());
        return Err(format!("CreateDBInstance error: {msg}"));
    }

    Ok(())
}

fn rds_query(body: &str, creds: &AwsCredentials) -> Result<String, String> {
    let host = format!("rds.{}.amazonaws.com", creds.region);
    let datetime = aws_sign::utc_now_iso8601(&creds.region);
    let (auth, payload_hash) = aws_sign::authorization_header(
        "POST",
        &host,
        "/",
        "",
        body,
        &datetime,
        &creds.region,
        "rds",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/x-www-form-urlencoded"),
    );

    let url = format!("https://{host}/");
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Host", &host)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, Some(body.to_string()))
        .map_err(|e| format!("RDS API HTTP error: {e}"))?;

    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();

    if status >= 400 {
        let msg = extract_tag(&text, "Message")
            .or_else(|| extract_tag(&text, "message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("RDS API error {status}: {msg}"));
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
