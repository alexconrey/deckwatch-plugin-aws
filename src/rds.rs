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
/// All fields are empty when the instance was just created and is not yet in
/// the `available` state — callers should treat an empty endpoint as
/// "provisioning in progress" and not block the deployment.
pub fn ensure_instance(cfg: &RdsConfig, creds: &AwsCredentials) -> Result<RdsInstance, String> {
    match describe_db_instance(&cfg.identifier, creds)? {
        Some(info) => {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: RDS instance {} status={}",
                cfg.identifier,
                info.status
            );
            let warnings = reconcile_backup_retention(&cfg.identifier, &info, creds);
            Ok(RdsInstance {
                endpoint: info.endpoint_address,
                resource_id: info.resource_id,
                master_secret_arn: info.master_secret_arn,
                warnings,
            })
        }
        None => {
            create_db_instance(cfg, creds)?;
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: RDS instance {} creation initiated",
                cfg.identifier
            );
            Ok(RdsInstance::default())
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// The parts of a DB instance callers need once it exists.
#[derive(Debug, Default)]
pub struct RdsInstance {
    /// Endpoint hostname.
    pub endpoint: String,
    /// `DbiResourceId` (e.g. `db-ABC…`), used in `rds-db:connect` ARNs.
    pub resource_id: String,
    /// ARN of the Secrets Manager secret holding the master credentials
    /// (`ManageMasterUserPassword`). Empty when RDS does not manage it.
    pub master_secret_arn: String,
    /// Problems the caller should surface (e.g. automated backups disabled).
    pub warnings: Vec<String>,
}

/// Bring an existing instance's automated-backup retention up to
/// `RDS_BACKUP_RETENTION_DAYS`. Only raises it, and only while the instance is
/// `available` (RDS rejects modifications otherwise; the next reconcile retries).
fn reconcile_backup_retention(
    identifier: &str,
    info: &DbInstanceInfo,
    creds: &AwsCredentials,
) -> Vec<String> {
    let Some(current) = info.backup_retention_days else {
        return vec![];
    };
    if info.status != "available" {
        return vec![];
    }
    let configured = crate::configured_backup_retention_days();
    match crate::retention_action(current, configured) {
        crate::RetentionAction::Keep => vec![],
        crate::RetentionAction::Raise(days) => {
            let body = format!(
                "Action=ModifyDBInstance&Version=2014-10-31&DBInstanceIdentifier={}\
                 &BackupRetentionPeriod={days}&ApplyImmediately=true",
                url_encode(identifier)
            );
            match rds_query(&body, creds) {
                Ok(_) => {
                    log!(
                        LogLevel::Info,
                        "deckwatch-plugin-aws: RDS {identifier} backup retention raised from {current} to {days} days"
                    );
                    vec![]
                }
                Err(e) => vec![format!(
                    "RDS {identifier}: could not raise backup retention from {current} to {days} days: {e}"
                )],
            }
        }
        crate::RetentionAction::WarnDisabled => vec![format!(
            "RDS {identifier} has automated backups disabled (retention 0). Re-enabling them \
             can cause a brief outage, so the plugin won't do it automatically; set \
             BackupRetentionPeriod to {configured} during a maintenance window."
        )],
    }
}

#[derive(Debug, Default)]
struct DbInstanceInfo {
    status: String,
    endpoint_address: String,
    resource_id: String,
    master_secret_arn: String,
    /// `BackupRetentionPeriod` in days, if present in the response.
    backup_retention_days: Option<u32>,
}

fn describe_db_instance(
    identifier: &str,
    creds: &AwsCredentials,
) -> Result<Option<DbInstanceInfo>, String> {
    let body =
        format!("Action=DescribeDBInstances&Version=2014-10-31&DBInstanceIdentifier={identifier}");
    // DBInstanceNotFound is returned as a 404 error by rds_query — catch it here
    // before propagating so ensure_instance knows to create the instance.
    let xml = match rds_query(&body, creds) {
        Ok(x) => x,
        Err(e) if e.contains("DBInstanceNotFound") || e.contains("not found") => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };

    if xml.contains("DBInstanceNotFound") {
        return Ok(None);
    }

    Ok(Some(DbInstanceInfo {
        status: extract_tag(&xml, "DBInstanceStatus").unwrap_or_default(),
        endpoint_address: extract_tag(&xml, "Address").unwrap_or_default(),
        resource_id: extract_tag(&xml, "DbiResourceId").unwrap_or_default(),
        master_secret_arn: extract_tag(&xml, "SecretArn").unwrap_or_default(),
        backup_retention_days: extract_tag(&xml, "BackupRetentionPeriod")
            .and_then(|v| v.parse().ok()),
    }))
}

fn create_db_instance(cfg: &RdsConfig, creds: &AwsCredentials) -> Result<(), String> {
    let multi_az = cfg.multi_az.to_string();
    let iam_auth = cfg.iam_auth.to_string();
    let retention = crate::configured_backup_retention_days().to_string();
    let backup_window = crate::configured_backup_window();

    let mut params: Vec<(&str, &str)> = vec![
        ("DBInstanceIdentifier", &cfg.identifier),
        ("DBInstanceClass", &cfg.instance_class),
        ("Engine", &cfg.engine),
        ("AllocatedStorage", &cfg.allocated_storage),
        ("DBName", &cfg.db_name),
        ("MultiAZ", &multi_az),
        ("EnableIAMDatabaseAuthentication", &iam_auth),
        ("MasterUsername", "dbadmin"),
        // Delegate password management to AWS Secrets Manager so no plaintext
        // credential appears in the API call or plugin state.
        ("ManageMasterUserPassword", "true"),
        ("StorageEncrypted", "true"),
        // Explicit retention: the API default is only 1 day of automated backups.
        ("BackupRetentionPeriod", &retention),
        ("CopyTagsToSnapshot", "true"),
        ("StorageType", "gp3"),
        ("PubliclyAccessible", "false"),
        ("DeletionProtection", "true"),
    ];

    if let Some(ref sg) = cfg.subnet_group {
        params.push(("DBSubnetGroupName", sg));
    }
    if let Some(ref window) = backup_window {
        params.push(("PreferredBackupWindow", window));
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
    let ep = crate::service_endpoint(&format!("rds.{}.amazonaws.com", creds.region))?;
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
        "rds",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/x-www-form-urlencoded"),
    );

    let url = format!("{}/", ep.base_url);
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
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

/// Delete the RDS instance, always taking a final snapshot named
/// `final_snapshot_id` first. Disables deletion protection before deleting.
///
/// Returns `Ok(false)` if the instance was already gone.
pub fn delete_instance(
    identifier: &str,
    final_snapshot_id: &str,
    creds: &AwsCredentials,
) -> Result<bool, String> {
    // 1. Disable deletion protection so the delete can proceed.
    // If the instance is already gone, treat it as success (idempotent deprovision).
    let modify_body = format!(
        "Action=ModifyDBInstance&Version=2014-10-31&DBInstanceIdentifier={}&DeletionProtection=false&ApplyImmediately=true",
        url_encode(identifier)
    );
    match rds_query(&modify_body, creds) {
        Ok(_) => {}
        Err(e) if e.contains("DBInstanceNotFound") || e.contains("not found") => {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: RDS instance {} already gone, deprovision complete",
                identifier
            );
            return Ok(false);
        }
        Err(e) => return Err(format!("failed to disable deletion protection: {e}")),
    }

    // 2. Delete the instance.
    // A final snapshot is always taken; there is deliberately no way to skip it.
    // Automated backups are retained too (until their retention period ends),
    // instead of RDS's default of deleting them with the instance.
    let delete_body = format!(
        "Action=DeleteDBInstance&Version=2014-10-31&DBInstanceIdentifier={}\
         &SkipFinalSnapshot=false&FinalDBSnapshotIdentifier={}\
         &DeleteAutomatedBackups=false",
        url_encode(identifier),
        url_encode(final_snapshot_id),
    );

    rds_query(&delete_body, creds).map_err(|e| format!("DeleteDBInstance failed: {e}"))?;

    Ok(true)
}
