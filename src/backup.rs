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
//! Content-Type: `application/x-amz-json-1.1`.
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
    creds: &AwsCredentials,
) -> Result<(), String> {
    // Derive account ID from the backup role ARN (field 4 in the colon-split).
    // arn:aws:iam::<account-id>:role/<name>
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
            let plan_body = format!(
                r#"{{"BackupPlanData":{{"BackupPlanName":"{plan_name}","Rules":[{{"RuleName":"scheduled-snapshot","TargetBackupVaultName":"Default","ScheduleExpression":"{schedule}","Lifecycle":{{"DeleteAfterDays":{retention}}}}}]}}}}"#
            );
            let resp = backup_post(region, "/backup/plans", &plan_body, creds)?;
            extract_json_str(&resp, "BackupPlanId").ok_or_else(|| {
                format!("configure_backup: could not parse BackupPlanId from response: {resp}")
            })?
        }
    };

    // ── 2. CreateBackupSelection (409 = already exists, safe to ignore) ───────
    let rds_arn = format!("arn:aws:rds:{region}:{account_id}:db:{rds_identifier}");
    let selection_name = format!("{rds_identifier}-selection");
    let selection_body = format!(
        r#"{{"BackupSelection":{{"SelectionName":"{selection_name}","IamRoleArn":"{backup_role_arn}","Resources":["{rds_arn}"]}}}}"#
    );

    let selection_path = format!("/backup/plans/{plan_id}/selections");
    backup_post(region, &selection_path, &selection_body, creds)?;

    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: AWS Backup plan {plan_id} configured for {rds_identifier}"
    );

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn backup_post(
    region: &str,
    path: &str,
    body: &str,
    creds: &AwsCredentials,
) -> Result<String, String> {
    let host = format!("backup.{region}.amazonaws.com");
    let datetime = aws_sign::utc_now_iso8601(region);

    let (auth, payload_hash) = aws_sign::authorization_header(
        "POST",
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
        Some("application/x-amz-json-1.1"),
    );

    let url = format!("https://{host}{path}");
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-amz-json-1.1")
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
        let msg = extract_json_str(&text, "message")
            .or_else(|| extract_json_str(&text, "Message"))
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
    Ok(find_plan_id_in_list(&json, plan_name))
}

/// Scan a `ListBackupPlans` JSON response for `plan_name` and return its ID.
fn find_plan_id_in_list(json: &str, plan_name: &str) -> Option<String> {
    let name_needle = format!("\"BackupPlanName\":\"{plan_name}\"");
    let pos = json.find(&name_needle)?;
    let obj_start = json[..pos].rfind('{').unwrap_or(0);
    let obj_end = json[pos..]
        .find('}')
        .map(|i| pos + i + 1)
        .unwrap_or(json.len());
    extract_json_str(&json[obj_start..obj_end], "BackupPlanId")
}

fn backup_get(region: &str, path: &str, creds: &AwsCredentials) -> Result<String, String> {
    let host = format!("backup.{region}.amazonaws.com");
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

    let url = format!("https://{host}{path}");
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
        let msg = extract_json_str(&text, "message")
            .or_else(|| extract_json_str(&text, "Message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("AWS Backup GET error {status}: {msg}"));
    }

    Ok(text)
}

/// Extract a string value from a flat JSON object by key (no serde dependency).
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
    fn find_plan_id_finds_matching_plan() {
        let json = r#"{"BackupPlansList":[{"BackupPlanId":"aaa","BackupPlanName":"other-backup"},{"BackupPlanId":"bbb111","BackupPlanName":"mydb-backup","VersionId":"v1"}]}"#;
        assert_eq!(
            find_plan_id_in_list(json, "mydb-backup"),
            Some("bbb111".to_string())
        );
    }

    #[test]
    fn find_plan_id_returns_none_when_not_found() {
        let json =
            r#"{"BackupPlansList":[{"BackupPlanId":"aaa","BackupPlanName":"other-backup"}]}"#;
        assert_eq!(find_plan_id_in_list(json, "mydb-backup"), None);
    }

    #[test]
    fn find_plan_id_empty_list() {
        let json = r#"{"BackupPlansList":[]}"#;
        assert_eq!(find_plan_id_in_list(json, "mydb-backup"), None);
    }

    #[test]
    fn extract_json_str_basic() {
        let json = r#"{"BackupPlanId":"abc123","Other":"val"}"#;
        assert_eq!(
            extract_json_str(json, "BackupPlanId"),
            Some("abc123".to_string())
        );
    }
}
