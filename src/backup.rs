//! AWS Backup plan and selection management.
//!
//! Snapshots are managed by the AWS Backup service — **not** by a Kubernetes
//! `CronJob`. This module produces no `kubernetes_resources`; all scheduling
//! state lives in AWS Backup.
//!
//! ## API
//!
//! AWS Backup uses a REST-JSON API at `backup.<region>.amazonaws.com`.
//! Sig V4 service name: `"backup"`.
//! Content-Type: `application/json` (REST-JSON, like the AWS SDKs send).
//!
//! ## Required IAM on `backup_role_arn`
//!
//! The IAM role passed as `backup_role_arn` must trust `backup.amazonaws.com`
//! and allow `rds:CreateDBSnapshot`, `rds:DescribeDBSnapshots`, and
//! `backup:*` on the target resource.
//!
//! ## Idempotency
//!
//! The plan and selection are named deterministically from the RDS identifier.
//! Calling `configure_backup` multiple times is safe — existing plans are left
//! in place; new ones are only created when the list call returns nothing.

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials};

// ── Public API ────────────────────────────────────────────────────────────────

/// Create or verify an AWS Backup plan and selection for the given RDS instance.
///
/// - `rds_identifier` — RDS DB instance identifier.
/// - `region`         — AWS region where the instance lives.
/// - `schedule`       — AWS EventBridge cron expression, e.g. `"cron(0 3 * * ? *)"`.
/// - `retention_days` — How many days to retain recovery points. Default: 7.
/// - `backup_role_arn`— ARN of an IAM role that `backup.amazonaws.com` can assume.
/// - `creds`          — Caller AWS credentials.
pub fn configure_backup(
    rds_identifier: &str,
    region: &str,
    schedule: &str,
    retention_days: i64,
    backup_role_arn: &str,
    tags: &[(String, String)],
    creds: &AwsCredentials,
) -> Result<(), String> {
    // Derive account ID from the backup role ARN (field 4 in the colon-split).
    // arn:<partition>:iam::<account-id>:role/<name>
    let account_id = backup_role_arn.split(':').nth(4).unwrap_or("*").to_string();

    let plan_name = format!("{rds_identifier}-backup");
    let retention = retention_days.max(1);

    // ── 1. Find or create BackupPlan ──────────────────────────────────────────
    // ListBackupPlans first — CreateBackupPlan is NOT idempotent and returns a
    // new plan ID on every call. We must not call it when the plan already exists.
    let plan_id = match find_backup_plan_id(&plan_name, region, creds)? {
        Some(id) => {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: AWS Backup plan '{plan_name}' already exists (id={id})"
            );
            id
        }
        None => {
            // AWS Backup is a REST-JSON API: CreateBackupPlan is
            // `PUT /backup/plans/` with a "BackupPlan" member and
            // Content-Type application/json. (It was previously sent as POST,
            // with "BackupPlanData" and the JSON-RPC content type.)
            let plan_tags: serde_json::Map<String, serde_json::Value> = tags
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            let plan_body = serde_json::json!({
                "BackupPlan": {
                    "BackupPlanName": plan_name,
                    "Rules": [{
                        "RuleName": "scheduled-snapshot",
                        "TargetBackupVaultName": "Default",
                        "ScheduleExpression": schedule,
                        "Lifecycle": { "DeleteAfterDays": retention },
                    }],
                },
                "BackupPlanTags": plan_tags,
            })
            .to_string();
            let resp = backup_put(region, "/backup/plans/", &plan_body, creds)?;
            crate::json_str_field(&resp, "BackupPlanId").ok_or_else(|| {
                format!("configure_backup: could not parse BackupPlanId from response: {resp}")
            })?
        }
    };

    // ── 2. CreateBackupSelection (409 = already exists, safe to ignore) ───────
    let rds_arn = crate::rds_instance_arn(region, &account_id, rds_identifier);
    let selection_name = format!("{rds_identifier}-selection");
    let selection_body = format!(
        r#"{{"BackupSelection":{{"SelectionName":"{selection_name}","IamRoleArn":"{backup_role_arn}","Resources":["{rds_arn}"]}}}}"#
    );

    let selection_path = format!("/backup/plans/{plan_id}/selections/");
    backup_put(region, &selection_path, &selection_body, creds)?;

    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: AWS Backup plan {plan_id} configured for {rds_identifier}"
    );

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn backup_put(
    region: &str,
    path: &str,
    body: &str,
    creds: &AwsCredentials,
) -> Result<String, String> {
    let ep = crate::service_endpoint(&format!("backup.{region}.amazonaws.com"))?;
    let host = ep.host.clone();
    let datetime = aws_sign::utc_now_iso8601(region);

    let (auth, payload_hash) = aws_sign::authorization_header(
        "PUT",
        &host,
        path,
        "",
        body,
        &datetime,
        region,
        "backup",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/json"),
    );

    let url = format!("{}{path}", ep.base_url);
    let mut req = HttpRequest::new(&url)
        .with_method("PUT")
        .with_header("Content-Type", "application/json")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, Some(body.to_string()))
        .map_err(|e| format!("AWS Backup API HTTP error: {e}"))?;

    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();

    if status >= 400 {
        // Already-exists (409) is not an error — the plan was already created.
        if status == 409 {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: AWS Backup resource at {path} already exists (409)"
            );
            return Ok(text);
        }
        let msg = crate::json_str_field(&text, "message")
            .or_else(|| crate::json_str_field(&text, "Message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("AWS Backup API error {status}: {msg}"));
    }

    Ok(text)
}

/// Call `ListBackupPlans` and return the `BackupPlanId` for `plan_name`, if found.
fn find_backup_plan_id(
    plan_name: &str,
    region: &str,
    creds: &AwsCredentials,
) -> Result<Option<String>, String> {
    let json = backup_get(region, "/backup/plans?MaxResults=100", creds)?;
    Ok(crate::backup_plan_id(&json, plan_name))
}

fn backup_get(region: &str, path: &str, creds: &AwsCredentials) -> Result<String, String> {
    let ep = crate::service_endpoint(&format!("backup.{region}.amazonaws.com"))?;
    let host = ep.host.clone();
    let datetime = aws_sign::utc_now_iso8601(region);

    let path_only = path.split('?').next().unwrap_or(path);
    let query = path.find('?').map(|i| &path[i + 1..]).unwrap_or("");

    let (auth, payload_hash) = aws_sign::authorization_header(
        "GET",
        &host,
        path_only,
        query,
        "",
        &datetime,
        region,
        "backup",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        None,
    );

    let url = format!("{}{path}", ep.base_url);
    let mut req = HttpRequest::new(&url)
        .with_method("GET")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, None::<String>)
        .map_err(|e| format!("AWS Backup GET HTTP error: {e}"))?;

    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();

    if status >= 400 {
        let msg = crate::json_str_field(&text, "message")
            .or_else(|| crate::json_str_field(&text, "Message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("AWS Backup GET error {status}: {msg}"));
    }

    Ok(text)
}
