//! Deckwatch plugin — provisions AWS resources (IAM, RDS, S3) with a unified
//! per-workload IAM role.
//!
//! ## WASM entry points
//!
//! - [`metadata`] — returns static plugin metadata; called once at load time.
//! - [`apply`] — provisions resources via the AWS API; called per deployment event.
//!
//! ## Host-side testing
//!
//! [`apply_inner`] is a pure function (no AWS calls) used by unit tests. It
//! exercises annotation parsing, env-var injection, and ServiceAccount YAML
//! generation without any extism linkage.

mod aws_sign;
#[cfg(target_arch = "wasm32")]
mod backup;
#[cfg(target_arch = "wasm32")]
mod iam;
#[cfg(target_arch = "wasm32")]
mod rds;
#[cfg(target_arch = "wasm32")]
mod s3;
#[cfg(target_arch = "wasm32")]
mod secretsmanager;
#[cfg(target_arch = "wasm32")]
mod sqs;
#[cfg(target_arch = "wasm32")]
mod sts;

// ConfigField, ConfigFieldType, and PluginResource are pure types — no WASM host
// functions needed. Import unconditionally so resource helpers can be unit-tested
// on the host target too.
use deckwatch_plugin_sdk::{
    ConfigField, ConfigFieldType, EnvVarSpec, PluginContext, PluginResource, PluginResult,
};
#[cfg(target_arch = "wasm32")]
use deckwatch_plugin_sdk::{
    McpTuningField, PluginMetadata, ResourceDeprovisionRequest, ResourceDeprovisionResult,
    ResourceProvisionRequest, ResourceProvisionResult, WantsServiceAccount,
};
#[cfg(target_arch = "wasm32")]
use extism_pdk::*;

#[cfg(any(target_arch = "wasm32", test))]
use serde_json::json;

// ── Annotation helpers ────────────────────────────────────────────────────────

fn ann<'a>(ctx: &'a PluginContext, key: &str) -> Option<&'a str> {
    ctx.annotations.get(key).map(|s| s.as_str())
}

fn ann_str(ctx: &PluginContext, key: &str) -> String {
    ann(ctx, key).unwrap_or("").to_string()
}

fn ann_bool(ctx: &PluginContext, key: &str, default: bool) -> bool {
    match ann(ctx, key) {
        Some("true") | Some("yes") | Some("1") => true,
        Some("false") | Some("no") | Some("0") => false,
        _ => default,
    }
}

// ── AWS Credentials ───────────────────────────────────────────────────────────

/// AWS credentials injected by deckwatch from `PluginConfig.config`.
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub region: String,
}

#[cfg(target_arch = "wasm32")]
impl AwsCredentials {
    /// Resolve credentials from the extism config namespace.
    ///
    /// Resolution order:
    /// 1. If `AWS_IDENTITY_TOKEN` + `AWS_ROLE_ARN` are present, call STS
    ///    `AssumeRoleWithWebIdentity` (unsigned) to obtain temporary credentials.
    ///    Deckwatch injects `AWS_IDENTITY_TOKEN` by reading the file at
    ///    `$AWS_WEB_IDENTITY_TOKEN_FILE` — the plugin never touches the filesystem.
    /// 2. Fall back to static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
    pub fn from_config() -> Result<Self, String> {
        // Determine region first — needed for the STS regional endpoint.
        let region = config::get("AWS_REGION")
            .ok()
            .flatten()
            .or_else(|| config::get("AWS_DEFAULT_REGION").ok().flatten())
            .unwrap_or_else(|| "us-east-1".to_string());

        // Try workload identity exchange first (IRSA / OIDC federation).
        if let Some(creds) = sts::try_assume_role_with_web_identity(&region)? {
            log!(
                LogLevel::Info,
                "deckwatch-plugin-aws: resolved credentials via AssumeRoleWithWebIdentity"
            );
            return Ok(creds);
        }

        // Fall back to static credentials.
        let access_key = config::get("AWS_ACCESS_KEY_ID")
            .map_err(|e| format!("AWS_ACCESS_KEY_ID not in plugin config: {e}"))?
            .ok_or("AWS_ACCESS_KEY_ID not set — provide static credentials or configure inherit_env_file_keys for workload identity")?;
        let secret_key = config::get("AWS_SECRET_ACCESS_KEY")
            .map_err(|e| format!("AWS_SECRET_ACCESS_KEY not in plugin config: {e}"))?
            .ok_or("AWS_SECRET_ACCESS_KEY not set in plugin config")?;
        let session_token = config::get("AWS_SESSION_TOKEN")
            .ok()
            .flatten()
            .filter(|s| !s.is_empty());
        Ok(Self {
            access_key,
            secret_key,
            session_token,
            region,
        })
    }
}

// ── Config structs ────────────────────────────────────────────────────────────

pub struct AwsConfig {
    pub enabled: bool,
    /// Logical application name used to key the shared IAM role and ServiceAccount.
    ///
    /// Derived from (in priority order):
    /// 1. `aws.deckwatch.io/app-name` annotation — explicit override.
    /// 2. `app.kubernetes.io/name` pod template label — standard k8s label.
    /// 3. `app` pod template label — common Helm/ArgoCD convention.
    /// 4. `deployment_name` — one per-deployment role/SA as the fallback.
    pub app_name: String,
    pub role_name: String,
    pub rds: Option<RdsConfig>,
    pub s3: Option<S3Config>,
    pub sqs: Option<SqsConfig>,
    pub ecr_enabled: bool,
    pub secretsmanager: Option<SecretsMgrConfig>,
}

/// Parsed RDS configuration from `rds.deckwatch.io/*` annotations.
pub struct RdsConfig {
    /// RDS DB instance identifier. Defaults to `<namespace>-<deployment>-db` (max 63 chars).
    pub identifier: String,
    /// Database engine: `"postgres"` (default) or `"mysql"`.
    pub engine: String,
    pub instance_class: String,
    /// Allocated storage in GiB.
    pub allocated_storage: String,
    /// Initial database name. Defaults to `"app"`.
    pub db_name: String,
    pub multi_az: bool,
    pub subnet_group: Option<String>,
    pub security_groups: Vec<String>,
    /// Use IAM database authentication instead of password auth.
    pub iam_auth: bool,
    /// AWS EventBridge cron expression for AWS Backup. `None` if not set.
    pub snapshot_schedule: Option<String>,
    /// AWS Backup retention days. Defaults to 7.
    pub snapshot_retention: i64,
    /// IAM role ARN granted to the AWS Backup service (`backup.amazonaws.com`).
    pub backup_role_arn: String,
    /// AWS region for this RDS instance. Defaults to `"us-east-1"`.
    pub region: String,
}

pub struct S3Config {
    pub bucket_name: String,
    pub region: String,
    pub versioning: bool,
    pub public_access_block: bool,
    pub lifecycle_days: Option<u32>,
}

pub struct SqsConfig {
    pub queue_name: String,
    pub fifo: bool,
    pub visibility_timeout: u32,
    pub retention_days: u32,
}

pub struct SecretsMgrConfig {
    /// ARNs of pre-existing secrets to grant `GetSecretValue` access to.
    pub secret_arns: Vec<String>,
    /// When true, create a managed (empty) secret for this workload.
    pub create_secret: bool,
    pub secret_name: String,
}

// ── Name-generation helpers ───────────────────────────────────────────────────

fn default_role_name(namespace: &str, deployment: &str) -> String {
    format!("{namespace}-{deployment}-role")
}

/// Generate an RDS-safe identifier (≤ 63 ASCII chars, alphanumeric + hyphens).
fn default_rds_identifier(namespace: &str, deployment: &str) -> String {
    let raw = format!("{namespace}-{deployment}-db");
    let sanitised: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitised.len() > 63 {
        sanitised[..63].to_string()
    } else {
        sanitised
    }
}

fn default_sqs_queue_name(namespace: &str, deployment: &str) -> String {
    format!("{namespace}-{deployment}-queue")
}

fn default_secret_name(namespace: &str, deployment: &str) -> String {
    format!("{namespace}/{deployment}")
}

#[cfg(any(target_arch = "wasm32", test))]
fn workload_sa_name(deployment: &str) -> String {
    format!("{deployment}-aws-sa")
}

/// IAM role name `provision()` creates for an application's RDS IRSA binding.
/// Stamped as `aws.deckwatch.io/role-name` so `apply()` reuses the same role.
#[cfg(target_arch = "wasm32")]
fn rds_role_name(namespace: &str, app: &str) -> String {
    format!("{namespace}-{app}-rds")
}

/// Database user the workload connects as. With IAM auth this is the app name
/// (the user granted `rds_iam`); otherwise the RDS master user.
fn rds_db_user(iam_auth: bool, app: &str) -> String {
    if iam_auth {
        app.to_string()
    } else {
        "dbadmin".to_string()
    }
}

/// Deployment annotations `provision()` stamps so `apply()` activates on
/// reconcile and resolves the *same* instance, IAM role, and ServiceAccount.
///
/// Without the identifier, `apply()` would fall back to
/// `<namespace>-<deployment>-db` and create a second instance; without the
/// role and app names it would create a second role and repoint the SA.
#[cfg(any(target_arch = "wasm32", test))]
fn rds_apply_annotations(
    app: &str,
    identifier: &str,
    engine: &str,
    instance_class: &str,
    db_name: &str,
    iam_auth: bool,
    role_name: &str,
) -> std::collections::HashMap<String, String> {
    [
        ("rds.deckwatch.io/enabled", "true"),
        ("rds.deckwatch.io/identifier", identifier),
        ("rds.deckwatch.io/engine", engine),
        ("rds.deckwatch.io/instance-class", instance_class),
        ("rds.deckwatch.io/db-name", db_name),
        (
            "rds.deckwatch.io/iam-auth",
            if iam_auth { "true" } else { "false" },
        ),
        ("aws.deckwatch.io/app-name", app),
        ("aws.deckwatch.io/role-name", role_name),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

// ── IAM database user bootstrap ───────────────────────────────────────────────
//
// With IAM auth the workload connects as a Postgres user that must exist and be
// granted `rds_iam`. RDS only creates the master user, and a WASM plugin cannot
// open a Postgres connection, so provision() emits a one-shot Job that does it.
//
// The Job runs under its own ServiceAccount whose IRSA role can read only this
// instance's master secret. An init container fetches the secret into a
// memory-backed emptyDir; the psql container reads it, runs idempotent SQL, and
// deletes it. The password never enters plugin state, a Kubernetes Secret, or
// the workload's role.

#[cfg(target_arch = "wasm32")]
const DEFAULT_BOOTSTRAP_AWSCLI_IMAGE: &str = "amazon/aws-cli:2.39.6";
#[cfg(target_arch = "wasm32")]
const DEFAULT_BOOTSTRAP_PSQL_IMAGE: &str = "postgres:18-alpine";

#[cfg(any(target_arch = "wasm32", test))]
fn bootstrap_name(app: &str) -> String {
    format!("{app}-db-bootstrap")
}

#[cfg(target_arch = "wasm32")]
fn bootstrap_role_name(namespace: &str, app: &str) -> String {
    format!("{namespace}-{app}-rds-bootstrap")
}

/// Idempotent SQL creating `db_user` for IAM auth with full use of `db_name`.
///
/// Both names are interpolated as quoted identifiers, so they are validated
/// against the character sets Kubernetes app names and RDS DB names allow.
#[cfg(any(target_arch = "wasm32", test))]
fn bootstrap_sql(db_user: &str, db_name: &str) -> Result<String, String> {
    let user_ok = !db_user.is_empty()
        && db_user.len() <= 63
        && db_user
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !user_ok {
        return Err(format!("unsupported database user name {db_user:?}"));
    }
    let name_ok = db_name.len() <= 63
        && db_name.starts_with(|c: char| c.is_ascii_alphabetic())
        && db_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !name_ok {
        return Err(format!("unsupported database name {db_name:?}"));
    }
    Ok(format!(
        r#"DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{db_user}') THEN
    CREATE ROLE "{db_user}" WITH LOGIN;
  END IF;
END
$$;
GRANT rds_iam TO "{db_user}";
GRANT CONNECT, CREATE, TEMPORARY ON DATABASE "{db_name}" TO "{db_user}";
GRANT USAGE, CREATE ON SCHEMA public TO "{db_user}";
"#
    ))
}

/// Inputs for [`db_bootstrap_manifests`].
#[cfg(any(target_arch = "wasm32", test))]
struct BootstrapSpec<'a> {
    namespace: &'a str,
    app: &'a str,
    role_arn: &'a str,
    master_secret_arn: &'a str,
    region: &'a str,
    host: &'a str,
    port: &'a str,
    db_name: &'a str,
    sql: &'a str,
    awscli_image: &'a str,
    psql_image: &'a str,
}

/// Escape a string for a container `command`/`args`/`env` value. Kubernetes
/// expands `$(VAR)` there and turns `$$` into `$`, which would otherwise mangle
/// shell variables and Postgres `$$` dollar quotes.
#[cfg(any(target_arch = "wasm32", test))]
fn k8s_literal(s: &str) -> String {
    s.replace('$', "$$")
}

/// FNV-1a over `s`, as 8 hex chars. Used to give each distinct Job spec its
/// own name; pod templates are immutable, so a changed spec cannot be applied
/// over an existing Job of the same name.
#[cfg(any(target_arch = "wasm32", test))]
fn short_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", h as u32)
}

/// Job name: `<app>-db-bootstrap-<hash>`, kept within the 63-char limit.
#[cfg(any(target_arch = "wasm32", test))]
fn bootstrap_job_name(app: &str, template: &serde_json::Value) -> String {
    let mut prefix = bootstrap_name(app);
    prefix.truncate(54);
    let prefix = prefix.trim_end_matches('-');
    format!("{prefix}-{}", short_hash(&template.to_string()))
}

/// ServiceAccount + Job that create the IAM-auth database user.
///
/// The Job name carries a hash of its pod template, so re-applying an
/// unchanged spec on every provision/refresh is a no-op while it exists, and a
/// changed spec (e.g. new image) creates a new Job instead of failing on the
/// immutable template. Once the TTL removes a Job, the next refresh re-runs
/// the (idempotent) SQL.
#[cfg(any(target_arch = "wasm32", test))]
fn db_bootstrap_manifests(spec: &BootstrapSpec) -> Vec<serde_json::Value> {
    let name = bootstrap_name(spec.app);
    let labels = json!({
        "app.kubernetes.io/managed-by": "deckwatch",
        "app.kubernetes.io/component": "db-bootstrap",
        "app.kubernetes.io/part-of": spec.app,
        "plugin": "deckwatch-plugin-aws",
    });
    let no_escalation = json!({ "allowPrivilegeEscalation": false });

    // Extract username/password from the secret JSON with busybox sed (no jq in
    // the image), then undo JSON backslash escapes in the password.
    let psql_script = r#"set -eu
PGUSER=$(sed -nE 's/.*"username" *: *"([^"]*)".*/\1/p' /work/master.json)
PGPASSWORD=$(sed -nE 's/.*"password" *: *"(([^"\\]|\\.)*)".*/\1/p' /work/master.json | sed -E 's/\\(.)/\1/g')
rm -f /work/master.json
export PGUSER PGPASSWORD
printf '%s\n' "$BOOTSTRAP_SQL" | psql -v ON_ERROR_STOP=1 -f -
echo "database user bootstrap complete""#;

    let sa = json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": name,
            "namespace": spec.namespace,
            "annotations": { "eks.amazonaws.com/role-arn": spec.role_arn },
            "labels": labels,
        },
    });

    let template = json!({
                "metadata": { "labels": labels },
                "spec": {
                    "serviceAccountName": name,
                    "restartPolicy": "Never",
                    "volumes": [{
                        "name": "work",
                        "emptyDir": { "medium": "Memory", "sizeLimit": "1Mi" },
                    }],
                    "initContainers": [{
                        "name": "fetch-master-secret",
                        "image": spec.awscli_image,
                        "command": [
                            "/bin/sh", "-c",
                            k8s_literal("aws secretsmanager get-secret-value --secret-id \"$MASTER_SECRET_ARN\" --query SecretString --output text > /work/master.json"),
                        ],
                        "env": [
                            { "name": "MASTER_SECRET_ARN", "value": k8s_literal(spec.master_secret_arn) },
                            { "name": "AWS_REGION", "value": k8s_literal(spec.region) },
                        ],
                        "volumeMounts": [{ "name": "work", "mountPath": "/work" }],
                        "securityContext": no_escalation,
                    }],
                    "containers": [{
                        "name": "create-db-user",
                        "image": spec.psql_image,
                        "command": ["/bin/sh", "-c", k8s_literal(psql_script)],
                        "env": [
                            { "name": "PGHOST", "value": k8s_literal(spec.host) },
                            { "name": "PGPORT", "value": k8s_literal(spec.port) },
                            { "name": "PGDATABASE", "value": k8s_literal(spec.db_name) },
                            { "name": "PGSSLMODE", "value": "require" },
                            { "name": "BOOTSTRAP_SQL", "value": k8s_literal(spec.sql) },
                        ],
                        "volumeMounts": [{ "name": "work", "mountPath": "/work" }],
                        "securityContext": no_escalation,
                    }],
                },
    });

    let job = json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": bootstrap_job_name(spec.app, &template),
            "namespace": spec.namespace,
            "labels": labels,
        },
        "spec": {
            "backoffLimit": 6,
            "activeDeadlineSeconds": 900,
            "ttlSecondsAfterFinished": 86400,
            "template": template,
        },
    });

    vec![sa, job]
}

/// Create the bootstrap IAM role (read-only access to this instance's master
/// secret) and return the ServiceAccount + Job manifests.
#[cfg(target_arch = "wasm32")]
#[allow(clippy::too_many_arguments)]
fn db_user_bootstrap(
    namespace: &str,
    app: &str,
    engine: &str,
    instance: &rds::RdsInstance,
    port: &str,
    db_name: &str,
    db_user: &str,
    creds: &AwsCredentials,
) -> Result<Vec<serde_json::Value>, String> {
    if engine != "postgres" {
        return Err(format!(
            "automatic user creation supports postgres only, not {engine}"
        ));
    }
    if instance.master_secret_arn.is_empty() {
        return Err("instance has no RDS-managed master secret".into());
    }
    let sql = bootstrap_sql(db_user, db_name)?;

    let role_name = bootstrap_role_name(namespace, app);
    let role_arn = iam::ensure_role(&role_name, namespace, &bootstrap_name(app), creds)
        .map_err(|e| format!("bootstrap IAM role {role_name}: {e}"))?;
    iam::attach_secretsmanager_policy(
        &role_name,
        std::slice::from_ref(&instance.master_secret_arn),
        creds,
    )
    .map_err(|e| format!("grant {role_name} read on master secret: {e}"))?;

    let cfg_or = |key: &str, default: &str| {
        config::get(key)
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default.to_string())
    };
    let awscli_image = cfg_or("DB_BOOTSTRAP_AWSCLI_IMAGE", DEFAULT_BOOTSTRAP_AWSCLI_IMAGE);
    let psql_image = cfg_or("DB_BOOTSTRAP_PSQL_IMAGE", DEFAULT_BOOTSTRAP_PSQL_IMAGE);

    Ok(db_bootstrap_manifests(&BootstrapSpec {
        namespace,
        app,
        role_arn: &role_arn,
        master_secret_arn: &instance.master_secret_arn,
        region: &creds.region,
        host: &instance.endpoint,
        port,
        db_name,
        sql: &sql,
        awscli_image: &awscli_image,
        psql_image: &psql_image,
    }))
}

fn engine_port(engine: &str) -> u16 {
    match engine {
        "mysql" | "mariadb" | "aurora-mysql" => 3306,
        _ => 5432,
    }
}

// ── Config parsing ────────────────────────────────────────────────────────────

/// Derive the logical application name shared across all deployments of an app.
///
/// Resolution order:
/// 1. `aws.deckwatch.io/app-name` annotation — operator-supplied explicit override.
/// 2. `app.kubernetes.io/name` pod template label — standard Kubernetes label.
/// 3. `app` pod template label — common Helm/ArgoCD shorthand.
/// 4. `deployment_name` — fallback gives one IAM role per deployment.
///
/// Using a consistent app-name across multiple deployments lets them share a
/// single IAM role and ServiceAccount rather than provisioning one each.
fn derive_app_name(ctx: &PluginContext) -> &str {
    if let Some(v) = ctx
        .annotations
        .get("aws.deckwatch.io/app-name")
        .map(String::as_str)
    {
        if !v.is_empty() {
            return v;
        }
    }
    if let Some(v) = ctx.labels.get("app.kubernetes.io/name").map(String::as_str) {
        if !v.is_empty() {
            return v;
        }
    }
    if let Some(v) = ctx.labels.get("app").map(String::as_str) {
        if !v.is_empty() {
            return v;
        }
    }
    ctx.deployment_name.as_str()
}

impl AwsConfig {
    pub fn from_context(ctx: &PluginContext) -> Self {
        let rds_enabled = ann_bool(ctx, "rds.deckwatch.io/enabled", false);
        let s3_enabled = ann_bool(ctx, "s3.deckwatch.io/enabled", false);
        let sqs_enabled = ann_bool(ctx, "sqs.deckwatch.io/enabled", false);
        let ecr_enabled = ann_bool(ctx, "ecr.deckwatch.io/enabled", false);
        let sm_arns_raw = ann_str(ctx, "secretsmanager.deckwatch.io/secret-arns");
        let sm_create = ann_bool(ctx, "secretsmanager.deckwatch.io/enabled", false);
        let sm_enabled = sm_create || !sm_arns_raw.is_empty();

        let aws_enabled = ann_bool(ctx, "aws.deckwatch.io/enabled", false)
            || rds_enabled
            || s3_enabled
            || sqs_enabled
            || ecr_enabled
            || sm_enabled;

        // Logical application name — shared across all deployments of the same app
        // so they all receive the same IAM role and ServiceAccount.
        let app_name = derive_app_name(ctx).to_string();

        let role_name = {
            let raw = ann_str(ctx, "aws.deckwatch.io/role-name");
            if raw.is_empty() {
                default_role_name(&ctx.namespace, &app_name)
            } else {
                raw
            }
        };

        let rds = if rds_enabled {
            Some(RdsConfig {
                identifier: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/identifier");
                    if raw.is_empty() {
                        default_rds_identifier(&ctx.namespace, &ctx.deployment_name)
                    } else {
                        raw
                    }
                },
                engine: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/engine");
                    if raw.is_empty() {
                        "postgres".to_string()
                    } else {
                        raw
                    }
                },
                instance_class: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/instance-class");
                    if raw.is_empty() {
                        "db.t3.micro".to_string()
                    } else {
                        raw
                    }
                },
                allocated_storage: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/allocated-storage");
                    if raw.is_empty() {
                        "20".to_string()
                    } else {
                        raw
                    }
                },
                db_name: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/db-name");
                    if raw.is_empty() {
                        "app".to_string()
                    } else {
                        raw
                    }
                },
                multi_az: ann_bool(ctx, "rds.deckwatch.io/multi-az", false),
                subnet_group: {
                    let ann_val = ann_str(ctx, "rds.deckwatch.io/subnet-group");
                    if !ann_val.is_empty() {
                        Some(ann_val)
                    } else {
                        #[cfg(target_arch = "wasm32")]
                        {
                            config::get("RDS_DEFAULT_SUBNET_GROUP")
                                .ok()
                                .flatten()
                                .filter(|s| !s.is_empty())
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            None
                        }
                    }
                },
                security_groups: {
                    let ann_val = ann_str(ctx, "rds.deckwatch.io/security-groups");
                    let raw = if !ann_val.is_empty() {
                        ann_val
                    } else {
                        #[cfg(target_arch = "wasm32")]
                        {
                            config::get("RDS_DEFAULT_SECURITY_GROUPS")
                                .ok()
                                .flatten()
                                .unwrap_or_default()
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            String::new()
                        }
                    };
                    if raw.is_empty() {
                        vec![]
                    } else {
                        raw.split(',').map(|s| s.trim().to_string()).collect()
                    }
                },
                iam_auth: {
                    let ann_val = ann(ctx, "rds.deckwatch.io/iam-auth");
                    match ann_val {
                        Some("true") | Some("yes") | Some("1") => true,
                        Some("false") | Some("no") | Some("0") => false,
                        _ => {
                            #[cfg(target_arch = "wasm32")]
                            {
                                config::get("RDS_DEFAULT_IAM_AUTH")
                                    .ok()
                                    .flatten()
                                    .map(|v| {
                                        matches!(v.to_lowercase().as_str(), "true" | "yes" | "1")
                                    })
                                    .unwrap_or(true)
                            }
                            #[cfg(not(target_arch = "wasm32"))]
                            {
                                false
                            }
                        }
                    }
                },
                snapshot_schedule: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/snapshot-schedule");
                    if raw.is_empty() {
                        None
                    } else {
                        Some(raw)
                    }
                },
                snapshot_retention: ann_str(ctx, "rds.deckwatch.io/snapshot-retention")
                    .parse::<i64>()
                    .unwrap_or(7),
                backup_role_arn: ann_str(ctx, "rds.deckwatch.io/backup-role-arn"),
                region: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/region");
                    if raw.is_empty() {
                        "us-east-1".to_string()
                    } else {
                        raw
                    }
                },
            })
        } else {
            None
        };

        let s3 = if s3_enabled {
            Some(S3Config {
                bucket_name: ann_str(ctx, "s3.deckwatch.io/bucket-name"),
                region: {
                    let raw = ann_str(ctx, "s3.deckwatch.io/region");
                    if raw.is_empty() {
                        "us-east-1".to_string()
                    } else {
                        raw
                    }
                },
                versioning: ann_bool(ctx, "s3.deckwatch.io/versioning", false),
                public_access_block: ann_bool(ctx, "s3.deckwatch.io/public-access-block", true),
                lifecycle_days: ann_str(ctx, "s3.deckwatch.io/lifecycle-days")
                    .parse::<u32>()
                    .ok()
                    .filter(|&d| d > 0),
            })
        } else {
            None
        };

        let sqs = if sqs_enabled {
            Some(SqsConfig {
                queue_name: {
                    let raw = ann_str(ctx, "sqs.deckwatch.io/queue-name");
                    if raw.is_empty() {
                        default_sqs_queue_name(&ctx.namespace, &ctx.deployment_name)
                    } else {
                        raw
                    }
                },
                fifo: ann_bool(ctx, "sqs.deckwatch.io/fifo", false),
                visibility_timeout: ann_str(ctx, "sqs.deckwatch.io/visibility-timeout")
                    .parse::<u32>()
                    .unwrap_or(30),
                retention_days: ann_str(ctx, "sqs.deckwatch.io/retention-days")
                    .parse::<u32>()
                    .unwrap_or(4),
            })
        } else {
            None
        };

        let secretsmanager = if sm_enabled {
            Some(SecretsMgrConfig {
                secret_arns: if sm_arns_raw.is_empty() {
                    vec![]
                } else {
                    sm_arns_raw
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                },
                create_secret: sm_create,
                secret_name: {
                    let raw = ann_str(ctx, "secretsmanager.deckwatch.io/secret-name");
                    if raw.is_empty() {
                        default_secret_name(&ctx.namespace, &ctx.deployment_name)
                    } else {
                        raw
                    }
                },
            })
        } else {
            None
        };

        AwsConfig {
            enabled: aws_enabled,
            app_name,
            role_name,
            rds,
            s3,
            sqs,
            ecr_enabled,
            secretsmanager,
        }
    }
}

// ── ServiceAccount YAML ───────────────────────────────────────────────────────

/// Build a Kubernetes `ServiceAccount` manifest with an IRSA role annotation.
///
/// Used by `provision()`, which has no structured `WantsServiceAccount` path.
/// Only emitted once the IAM role is confirmed to exist.
#[cfg(target_arch = "wasm32")]
fn service_account_yaml(sa_name: &str, role_arn: &str, namespace: &str) -> serde_json::Value {
    json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": sa_name,
            "namespace": namespace,
            "annotations": {
                "eks.amazonaws.com/role-arn": role_arn,
            },
            "labels": {
                "managed-by": "deckwatch",
                "plugin": "deckwatch-plugin-aws",
            },
        },
    })
}

// ── apply_inner (pure — no AWS API calls) ─────────────────────────────────────

/// Build a [`PluginResult`] purely from context annotations, without making any
/// AWS API calls.
///
/// This is the testable core of the plugin. The WASM [`apply`] entry point calls
/// this for the static portions, then augments the result with live data from
/// the AWS API.
///
/// `bucket_prefix` mirrors the `BUCKET_PREFIX` extism config key. Pass `""` in
/// tests that do not exercise prefix behaviour.
pub fn apply_inner(ctx: &PluginContext, bucket_prefix: &str) -> PluginResult {
    let cfg = AwsConfig::from_context(ctx);
    if !cfg.enabled {
        return PluginResult::default();
    }

    let mut result = PluginResult::default();

    // NOTE: wants_service_account is intentionally NOT set here. apply_inner is
    // the fallback used when ensure_role() fails. Requesting the SA in the
    // fallback binds the pod to an SA with no IRSA role, so every AWS call from
    // the workload fails. apply_with_aws requests the SA only after the IAM
    // role is confirmed to exist.

    // ── RDS env vars ──────────────────────────────────────────────────────────
    if let Some(ref rds) = cfg.rds {
        let port = engine_port(&rds.engine);
        result
            .env_vars
            .push(EnvVarSpec::value("DB_ENGINE", &rds.engine));
        result
            .env_vars
            .push(EnvVarSpec::value("DB_PORT", port.to_string()));
        result
            .env_vars
            .push(EnvVarSpec::value("POSTGRES_PORT", port.to_string()));
        result
            .env_vars
            .push(EnvVarSpec::value("DB_NAME", &rds.db_name));
        result
            .env_vars
            .push(EnvVarSpec::value("POSTGRES_DB", &rds.db_name));
        result.env_vars.push(EnvVarSpec::value(
            "POSTGRES_USER",
            rds_db_user(rds.iam_auth, &cfg.app_name),
        ));
        if rds.iam_auth {
            result
                .env_vars
                .push(EnvVarSpec::value("DB_IAM_AUTH", "true"));
        }
    }

    // ── S3 env vars ───────────────────────────────────────────────────────────
    if let Some(ref s3) = cfg.s3 {
        let full_bucket = format!("{}{}", bucket_prefix, s3.bucket_name);
        result
            .env_vars
            .push(EnvVarSpec::value("S3_BUCKET", &full_bucket));
        result
            .env_vars
            .push(EnvVarSpec::value("S3_REGION", &s3.region));
        result
            .env_vars
            .push(EnvVarSpec::value("AWS_REGION", &s3.region));
    }

    // ── SQS (queue name known statically) ─────────────────────────────────────
    if let Some(ref sqs) = cfg.sqs {
        let name = if sqs.fifo && !sqs.queue_name.ends_with(".fifo") {
            format!("{}.fifo", sqs.queue_name)
        } else {
            sqs.queue_name.clone()
        };
        result.env_vars.push(EnvVarSpec::value("QUEUE_NAME", &name));
    }

    // ── Secrets Manager (secret name known statically when creating) ───────────
    if let Some(ref sm) = cfg.secretsmanager {
        if sm.create_secret {
            result
                .env_vars
                .push(EnvVarSpec::value("SM_SECRET_NAME", &sm.secret_name));
        }
    }

    // ── Plugin outputs ────────────────────────────────────────────────────────
    // role_arn and service_account_name are set by apply_with_aws after the
    // IAM role is confirmed to exist. Placeholder empty values here allow
    // downstream plugins to detect that this plugin ran.
    result.outputs.insert("role_arn".into(), String::new());
    result
        .outputs
        .insert("service_account_name".into(), String::new());

    result
}

// ── WASM-only: apply_with_aws ─────────────────────────────────────────────────

/// Full apply: create/verify IAM role, provision RDS/S3, configure AWS Backup,
/// then return the augmented result.
#[cfg(target_arch = "wasm32")]
fn apply_with_aws(
    ctx: &PluginContext,
    creds: &AwsCredentials,
    bucket_prefix: &str,
) -> PluginResult {
    let cfg = AwsConfig::from_context(ctx);
    if !cfg.enabled {
        return PluginResult::default();
    }

    let sa = workload_sa_name(&cfg.app_name);

    // ── 1. Ensure IAM role (OIDC-scoped trust policy) ─────────────────────────
    let role_arn = match iam::ensure_role(&cfg.role_name, &ctx.namespace, &sa, creds) {
        Ok(arn) => arn,
        Err(e) => {
            log!(
                LogLevel::Error,
                "deckwatch-plugin-aws: ensure_role failed: {e}"
            );
            // Fall back to static result so the deployment isn't blocked.
            return apply_inner(ctx, bucket_prefix);
        }
    };

    // ── 2. RDS ────────────────────────────────────────────────────────────────
    let rds_endpoint = if let Some(ref rds_cfg) = cfg.rds {
        match rds::ensure_instance(rds_cfg, creds) {
            Ok(instance) => {
                // rds-db:connect is scoped to the DbiResourceId, which is only
                // known once the instance exists; the next reconcile attaches it.
                if rds_cfg.iam_auth && !instance.resource_id.is_empty() {
                    let db_user = rds_db_user(true, &cfg.app_name);
                    if let Err(e) = iam::attach_rds_policy(
                        &cfg.role_name,
                        &instance.resource_id,
                        &db_user,
                        &creds.region,
                        creds,
                    ) {
                        log!(
                            LogLevel::Warn,
                            "deckwatch-plugin-aws: attach_rds_policy: {e}"
                        );
                    }
                }
                if let Some(ref schedule) = rds_cfg.snapshot_schedule {
                    if let Err(e) = backup::configure_backup(
                        &rds_cfg.identifier,
                        &creds.region,
                        schedule,
                        rds_cfg.snapshot_retention,
                        &rds_cfg.backup_role_arn,
                        creds,
                    ) {
                        log!(
                            LogLevel::Warn,
                            "deckwatch-plugin-aws: configure_backup: {e}"
                        );
                    }
                }
                instance.endpoint
            }
            Err(e) => {
                log!(
                    LogLevel::Error,
                    "deckwatch-plugin-aws: ensure_instance: {e}"
                );
                String::new()
            }
        }
    } else {
        String::new()
    };

    // ── 3. S3 ─────────────────────────────────────────────────────────────────
    let s3_bucket = if let Some(ref s3_cfg) = cfg.s3 {
        let full_bucket = format!("{}{}", bucket_prefix, s3_cfg.bucket_name);
        match s3::ensure_bucket(s3_cfg, &full_bucket, creds) {
            Ok(()) => {
                if let Err(e) = iam::attach_s3_policy(&cfg.role_name, &full_bucket, creds) {
                    log!(
                        LogLevel::Warn,
                        "deckwatch-plugin-aws: attach_s3_policy: {e}"
                    );
                }
            }
            Err(e) => {
                log!(LogLevel::Error, "deckwatch-plugin-aws: ensure_bucket: {e}");
            }
        }
        full_bucket
    } else {
        String::new()
    };

    // ── 4. SQS ────────────────────────────────────────────────────────────────
    let queue_url = if let Some(ref sqs_cfg) = cfg.sqs {
        match sqs::ensure_queue(sqs_cfg, creds) {
            Ok(info) => {
                if let Err(e) = iam::attach_sqs_policy(&cfg.role_name, &info.queue_arn, creds) {
                    log!(
                        LogLevel::Warn,
                        "deckwatch-plugin-aws: attach_sqs_policy: {e}"
                    );
                }
                info.queue_url
            }
            Err(e) => {
                log!(LogLevel::Error, "deckwatch-plugin-aws: ensure_queue: {e}");
                String::new()
            }
        }
    } else {
        String::new()
    };

    // ── 5. ECR ────────────────────────────────────────────────────────────────
    if cfg.ecr_enabled {
        if let Err(e) = iam::attach_ecr_policy(&cfg.role_name, creds) {
            log!(
                LogLevel::Warn,
                "deckwatch-plugin-aws: attach_ecr_policy: {e}"
            );
        }
    }

    // ── 6. Secrets Manager ────────────────────────────────────────────────────
    let sm_secret_arn = if let Some(ref sm_cfg) = cfg.secretsmanager {
        let mut all_arns = sm_cfg.secret_arns.clone();

        let created_arn = if sm_cfg.create_secret {
            let desc = format!(
                "Managed by deckwatch for {}/{}",
                ctx.namespace, ctx.deployment_name
            );
            match secretsmanager::ensure_secret(&sm_cfg.secret_name, &desc, creds) {
                Ok(arn) => {
                    all_arns.push(arn.clone());
                    arn
                }
                Err(e) => {
                    log!(LogLevel::Error, "deckwatch-plugin-aws: ensure_secret: {e}");
                    String::new()
                }
            }
        } else {
            String::new()
        };

        if !all_arns.is_empty() {
            if let Err(e) = iam::attach_secretsmanager_policy(&cfg.role_name, &all_arns, creds) {
                log!(
                    LogLevel::Warn,
                    "deckwatch-plugin-aws: attach_secretsmanager_policy: {e}"
                );
            }
        }

        created_arn
    } else {
        String::new()
    };

    // ── 7. Build result ───────────────────────────────────────────────────────
    let mut result = apply_inner(ctx, bucket_prefix);

    // The IAM role is confirmed to exist, so request the SA with its ARN.
    // Deckwatch will create-or-patch the SA with the IRSA annotation.
    result.wants_service_account = Some(WantsServiceAccount {
        name: sa.clone(),
        irsa_role_arn: role_arn.clone(),
    });

    result.outputs.insert("role_arn".into(), role_arn);
    result.outputs.insert("service_account_name".into(), sa);

    // RDS: emit DB_HOST when available; DB_STATUS signals provisioning state.
    if cfg.rds.is_some() {
        if rds_endpoint.is_empty() {
            result
                .env_vars
                .push(EnvVarSpec::value("DB_STATUS", "provisioning"));
            result
                .outputs
                .insert("db_status".into(), "provisioning".into());
        } else {
            result
                .env_vars
                .push(EnvVarSpec::value("DB_HOST", &rds_endpoint));
            result
                .env_vars
                .push(EnvVarSpec::value("POSTGRES_HOST", &rds_endpoint));
            result
                .env_vars
                .push(EnvVarSpec::value("DB_STATUS", "available"));
            result.outputs.insert("rds_endpoint".into(), rds_endpoint);
            result
                .outputs
                .insert("db_status".into(), "available".into());
        }
    }

    if !s3_bucket.is_empty() {
        result.outputs.insert("s3_bucket".into(), s3_bucket);
    }
    if !queue_url.is_empty() {
        result
            .env_vars
            .push(EnvVarSpec::value("QUEUE_URL", &queue_url));
        result.outputs.insert("queue_url".into(), queue_url);
    }
    if !sm_secret_arn.is_empty() {
        result
            .env_vars
            .push(EnvVarSpec::value("SM_SECRET_ARN", &sm_secret_arn));
        result.outputs.insert("sm_secret_arn".into(), sm_secret_arn);
    }

    result
}

// ── WASM entry points ─────────────────────────────────────────────────────────

/// Return static plugin metadata. Called once by deckwatch at load time to build
/// the plugin dependency graph.
#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn metadata() -> FnResult<Json<PluginMetadata>> {
    Ok(Json(PluginMetadata {
        name: "aws".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        description: "Provisions AWS resources (IAM, RDS, S3, SQS, Secrets Manager) with a unified per-workload IAM role".into(),
        provides: vec![
            "aws:iam-role".into(),
            "aws:service-account".into(),
            "aws:rds-connection".into(),
            "aws:s3-bucket".into(),
            "aws:sqs-queue".into(),
            "aws:secret-access".into(),
            "aws:ecr-pull".into(),
        ],
        depends_on: vec![],
        optional_depends_on: vec![],
        config_schema: vec![
            ConfigField { key: "AWS_REGION".into(), label: "AWS Region".into(), description: "Region for provisioned resources.".into(), field_type: ConfigFieldType::String, default: Some("us-east-1".into()), required: true, options: vec![], env_source: Some("AWS_REGION".into()) },
            ConfigField { key: "OIDC_PROVIDER_ARN".into(), label: "OIDC Provider ARN".into(), description: "ARN of the EKS OIDC provider (arn:aws:iam::<account>:oidc-provider/<url>). Required for IRSA.".into(), field_type: ConfigFieldType::String, default: None, required: false, options: vec![], env_source: None },
            ConfigField { key: "IAM_ENDPOINT".into(), label: "IAM Endpoint".into(), description: "Override IAM hostname. Auto-detected (iam.us-gov.amazonaws.com for GovCloud).".into(), field_type: ConfigFieldType::String, default: None, required: false, options: vec![], env_source: None },
            ConfigField { key: "IAM_SIGNING_REGION".into(), label: "IAM Signing Region".into(), description: "Override Sig V4 region for IAM. Auto-detected from region.".into(), field_type: ConfigFieldType::String, default: None, required: false, options: vec![], env_source: None },
            ConfigField { key: "ROLE_PATH".into(), label: "IAM Role Path".into(), description: "Path prefix for created roles. Must start and end with /.".into(), field_type: ConfigFieldType::String, default: Some("/deckwatch-plugin/".into()), required: false, options: vec![], env_source: None },
            ConfigField { key: "BUCKET_PREFIX".into(), label: "S3 Bucket Prefix".into(), description: "Prepended to all S3 bucket names (e.g. myorg-).".into(), field_type: ConfigFieldType::String, default: Some("".into()), required: false, options: vec![], env_source: None },
            ConfigField { key: "AWS_ACCESS_KEY_ID".into(), label: "Access Key ID".into(), description: "Static AWS access key. Leave blank when using IRSA.".into(), field_type: ConfigFieldType::Secret, default: None, required: false, options: vec![], env_source: Some("AWS_ACCESS_KEY_ID".into()) },
            ConfigField { key: "AWS_SECRET_ACCESS_KEY".into(), label: "Secret Access Key".into(), description: "Static AWS secret key. Leave blank when using IRSA.".into(), field_type: ConfigFieldType::Secret, default: None, required: false, options: vec![], env_source: Some("AWS_SECRET_ACCESS_KEY".into()) },
            ConfigField { key: "AWS_SESSION_TOKEN".into(), label: "Session Token".into(), description: "Temporary session token for assumed-role or SSO credentials. Leave blank when using IRSA.".into(), field_type: ConfigFieldType::Secret, default: None, required: false, options: vec![], env_source: Some("AWS_SESSION_TOKEN".into()) },
            ConfigField { key: "RDS_SKIP_FINAL_SNAPSHOT".into(), label: "Skip RDS Final Snapshot".into(), description: "Set to true to skip the final snapshot when deleting an RDS instance. Default: false (snapshot is always taken).".into(), field_type: ConfigFieldType::Bool, default: Some("false".into()), required: false, options: vec![], env_source: None },
            ConfigField { key: "RDS_DEFAULT_SUBNET_GROUP".into(), label: "RDS Default Subnet Group".into(), description: "DB subnet group name for all provisioned RDS instances. Required to place instances in the correct VPC.".into(), field_type: ConfigFieldType::String, default: None, required: false, options: vec![], env_source: None },
            ConfigField { key: "RDS_DEFAULT_SECURITY_GROUPS".into(), label: "RDS Default Security Groups".into(), description: "Comma-separated VPC security group IDs applied to all provisioned RDS instances.".into(), field_type: ConfigFieldType::String, default: None, required: false, options: vec![], env_source: None },
            ConfigField { key: "RDS_DEFAULT_IAM_AUTH".into(), label: "RDS IAM Auth by Default".into(), description: "Enable IAM database authentication on all provisioned RDS instances. Default: true.".into(), field_type: ConfigFieldType::Bool, default: Some("true".into()), required: false, options: vec![], env_source: None },
            ConfigField { key: "DB_BOOTSTRAP_AWSCLI_IMAGE".into(), label: "DB Bootstrap AWS CLI Image".into(), description: "Image for the init container that reads the RDS master secret when creating the IAM database user.".into(), field_type: ConfigFieldType::String, default: Some(DEFAULT_BOOTSTRAP_AWSCLI_IMAGE.into()), required: false, options: vec![], env_source: None },
            ConfigField { key: "DB_BOOTSTRAP_PSQL_IMAGE".into(), label: "DB Bootstrap psql Image".into(), description: "Image with psql used to create the IAM database user. Match or exceed the RDS engine major version.".into(), field_type: ConfigFieldType::String, default: Some(DEFAULT_BOOTSTRAP_PSQL_IMAGE.into()), required: false, options: vec![], env_source: None },
        ],
        resources: vec![rds_resource(), s3_resource(), sqs_resource(), secretsmanager_resource()],
        mcp_tuning_fields: vec![
            McpTuningField {
                key: "rds_naming_convention".into(),
                label: "RDS Instance Naming Convention".into(),
                description: "Convention for naming RDS instances created by this plugin. \
                              Used by the AI agent when suggesting identifiers.".into(),
                placeholder: "k2-{namespace}-{app}".into(),
                default: None,
            },
            McpTuningField {
                key: "s3_bucket_prefix_convention".into(),
                label: "S3 Bucket Naming Convention".into(),
                description: "Convention for naming S3 buckets created by this plugin. \
                              Prepended or combined with the application name.".into(),
                placeholder: "k2-{namespace}-{app}-".into(),
                default: None,
            },
            McpTuningField {
                key: "iam_role_path".into(),
                label: "IAM Role Path".into(),
                description: "Path prefix for IAM roles created by this plugin. \
                              Must start and end with /. Mirrors the ROLE_PATH config key.".into(),
                placeholder: "/deckwatch-plugin/".into(),
                default: Some("/deckwatch-plugin/".into()),
            },
            McpTuningField {
                key: "preferred_rds_instance_class".into(),
                label: "Preferred RDS Instance Class".into(),
                description: "Default RDS instance class to suggest when the operator does not \
                              specify one. e.g. db.t3.micro for dev, db.r6g.large for prod.".into(),
                placeholder: "db.t3.micro".into(),
                default: None,
            },
        ],
    }))
}

// ── Resource declarations ─────────────────────────────────────────────────────
// No #[cfg(target_arch = "wasm32")] — these are pure struct constructors that
// must be testable on the host target to catch metadata() regressions.
// `pub` so the host compiler doesn't flag them as dead code (they're used by
// `metadata()` which is wasm32-only, and by host-side unit tests).

pub fn rds_resource() -> PluginResource {
    PluginResource {
        id: "rds".into(),
        label: "RDS Database".into(),
        icon: "mdi-database".into(),
        description: "Provision an Amazon RDS instance for this application.".into(),
        singleton: true,
        fields: vec![
            ConfigField {
                key: "identifier".into(),
                label: "DB Identifier".into(),
                description: "RDS instance identifier (default: {namespace}-{app_name}-db)".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "engine".into(),
                label: "Engine".into(),
                description: "Database engine: postgres or mysql".into(),
                field_type: ConfigFieldType::Select,
                default: Some("postgres".into()),
                required: false,
                options: vec!["postgres".into(), "mysql".into()],
                env_source: None,
            },
            ConfigField {
                key: "instance_class".into(),
                label: "Instance Class".into(),
                description: "RDS instance class".into(),
                field_type: ConfigFieldType::String,
                default: Some("db.t3.micro".into()),
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "db_name".into(),
                label: "Database Name".into(),
                description: "Name for the initial database".into(),
                field_type: ConfigFieldType::String,
                default: Some("app".into()),
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "iam_auth".into(),
                label: "IAM Authentication".into(),
                description: "Use IAM database authentication instead of a password. Provisions an IRSA role with rds-db:connect for the workload. Defaults to the RDS_DEFAULT_IAM_AUTH plugin setting.".into(),
                field_type: ConfigFieldType::Bool,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
        ],
        output_keys: vec![
            "DB_HOST".into(),
            "DB_PORT".into(),
            "DB_ENGINE".into(),
            "DB_NAME".into(),
            "DB_IAM_AUTH".into(),
            "POSTGRES_HOST".into(),
            "POSTGRES_PORT".into(),
            "POSTGRES_DB".into(),
            "POSTGRES_USER".into(),
        ],
    }
}

pub fn s3_resource() -> PluginResource {
    PluginResource {
        id: "s3".into(),
        label: "S3 Bucket".into(),
        icon: "mdi-bucket".into(),
        description: "Provision an Amazon S3 bucket for this application.".into(),
        singleton: true,
        fields: vec![
            ConfigField {
                key: "bucket_name".into(),
                label: "Bucket Name".into(),
                description: "S3 bucket name (a prefix will be applied automatically)".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: true,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "region".into(),
                label: "Region".into(),
                description: "AWS region for the bucket (defaults to credentials region)".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
        ],
        output_keys: vec!["S3_BUCKET".into(), "S3_REGION".into(), "AWS_REGION".into()],
    }
}

pub fn sqs_resource() -> PluginResource {
    PluginResource {
        id: "sqs".into(),
        label: "SQS Queue".into(),
        icon: "mdi-message-queue".into(),
        description: "Provision an Amazon SQS queue for this application.".into(),
        singleton: true,
        fields: vec![
            ConfigField {
                key: "queue_name".into(),
                label: "Queue Name".into(),
                description: "SQS queue name (default: {namespace}-{app_name}-queue)".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "fifo".into(),
                label: "FIFO Queue".into(),
                description: "Enable FIFO ordering and exactly-once processing".into(),
                field_type: ConfigFieldType::Bool,
                default: Some("false".into()),
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "visibility_timeout".into(),
                label: "Visibility Timeout (s)".into(),
                description: "Seconds a received message is hidden from other consumers".into(),
                field_type: ConfigFieldType::String,
                default: Some("30".into()),
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "retention_days".into(),
                label: "Retention (days)".into(),
                description: "Days to retain undelivered messages (max 14)".into(),
                field_type: ConfigFieldType::String,
                default: Some("4".into()),
                required: false,
                options: vec![],
                env_source: None,
            },
        ],
        output_keys: vec!["QUEUE_URL".into(), "QUEUE_NAME".into()],
    }
}

pub fn secretsmanager_resource() -> PluginResource {
    PluginResource {
        id: "secretsmanager".into(),
        label: "Secrets Manager".into(),
        icon: "mdi-key-variant".into(),
        description: "Create an empty AWS Secrets Manager secret for this application. Populate the value manually or via CI.".into(),
        singleton: true,
        fields: vec![ConfigField {
            key: "secret_name".into(),
            label: "Secret Name".into(),
            description: "Secret name or path (default: {namespace}/{app_name})".into(),
            field_type: ConfigFieldType::String,
            default: None,
            required: false,
            options: vec![],
            env_source: None,
        }],
        output_keys: vec!["SM_SECRET_ARN".into(), "SM_SECRET_NAME".into()],
    }
}

// ── WASM entry point: provision ───────────────────────────────────────────────

/// Provision a single infrastructure resource on behalf of an application.
///
/// Called by deckwatch when an operator submits the provisioning form for a
/// resource declared in [`metadata`]. The result's `state` map is persisted at
/// application level and injected as env vars into all deployments on the next
/// reconcile cycle.
#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn provision(
    Json(req): Json<ResourceProvisionRequest>,
) -> FnResult<Json<ResourceProvisionResult>> {
    let mut result = ResourceProvisionResult::default();

    let creds = match AwsCredentials::from_config() {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("credentials error: {e}"));
            return Ok(Json(result));
        }
    };

    match req.resource_id.as_str() {
        "rds" => {
            let identifier = req
                .fields
                .get("identifier")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| default_rds_identifier(&req.namespace, &req.application_name));
            let engine = req
                .fields
                .get("engine")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "postgres".to_string());
            let instance_class = req
                .fields
                .get("instance_class")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "db.t3.micro".to_string());
            let db_name = req
                .fields
                .get("db_name")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "app".to_string());
            let subnet_group = config::get("RDS_DEFAULT_SUBNET_GROUP")
                .ok()
                .flatten()
                .filter(|s| !s.is_empty());
            let security_groups: Vec<String> = config::get("RDS_DEFAULT_SECURITY_GROUPS")
                .ok()
                .flatten()
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            // The iam_auth form field wins when set; otherwise fall back to the
            // RDS_DEFAULT_IAM_AUTH plugin setting (default true).
            let iam_auth = req
                .fields
                .get("iam_auth")
                .filter(|s| !s.is_empty())
                .cloned()
                .or_else(|| config::get("RDS_DEFAULT_IAM_AUTH").ok().flatten())
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "yes" | "1"))
                .unwrap_or(true);

            let cfg = RdsConfig {
                identifier: identifier.clone(),
                engine: engine.clone(),
                instance_class: instance_class.clone(),
                allocated_storage: "20".to_string(),
                db_name: db_name.clone(),
                multi_az: false,
                subnet_group,
                security_groups,
                iam_auth,
                snapshot_schedule: None,
                snapshot_retention: 7,
                backup_role_arn: String::new(),
                region: creds.region.clone(),
            };

            let db_user = rds_db_user(iam_auth, &req.application_name);
            let role_name = rds_role_name(&req.namespace, &req.application_name);

            match rds::ensure_instance(&cfg, &creds) {
                Ok(instance) => {
                    let port = engine_port(&engine).to_string();
                    let endpoint = instance.endpoint.clone();
                    let resource_id = instance.resource_id.clone();
                    if endpoint.is_empty() {
                        result
                            .state
                            .insert("DB_STATUS".into(), "provisioning".into());
                    } else {
                        // Create a workload IAM role and ServiceAccount for IRSA so
                        // the application pod can generate RDS IAM auth tokens without
                        // storing any credentials.
                        if iam_auth && !resource_id.is_empty() {
                            let sa_name = workload_sa_name(&req.application_name);
                            match iam::ensure_role(&role_name, &req.namespace, &sa_name, &creds) {
                                Ok(role_arn) => {
                                    if let Err(e) = iam::attach_rds_policy(
                                        &role_name,
                                        &resource_id,
                                        &db_user,
                                        &creds.region,
                                        &creds,
                                    ) {
                                        log!(
                                            LogLevel::Warn,
                                            "deckwatch-plugin-aws: attach_rds_policy: {e}"
                                        );
                                        result.warnings.push(format!(
                                            "attach rds-db:connect policy to {role_name}: {e}"
                                        ));
                                    }
                                    result.state.insert("DB_ROLE_ARN".into(), role_arn.clone());
                                    result.kubernetes_resources.push(service_account_yaml(
                                        &sa_name,
                                        &role_arn,
                                        &req.namespace,
                                    ));
                                    result.state.insert("DB_SA_NAME".into(), sa_name);

                                    // Create the IAM-auth database user. Nothing else
                                    // does, and without it Postgres rejects the token.
                                    match db_user_bootstrap(
                                        &req.namespace,
                                        &req.application_name,
                                        &engine,
                                        &instance,
                                        &port,
                                        &db_name,
                                        &db_user,
                                        &creds,
                                    ) {
                                        Ok(resources) => {
                                            result.kubernetes_resources.extend(resources)
                                        }
                                        Err(e) => {
                                            log!(
                                                LogLevel::Warn,
                                                "deckwatch-plugin-aws: db user bootstrap: {e}"
                                            );
                                            result.warnings.push(format!(
                                                "database user {db_user} not bootstrapped; create it and GRANT rds_iam manually: {e}"
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    log!(
                                        LogLevel::Warn,
                                        "deckwatch-plugin-aws: ensure_role for RDS: {e}"
                                    );
                                    result.warnings.push(format!(
                                        "IAM role {role_name} not created; pods cannot use RDS IAM auth until it exists: {e}"
                                    ));
                                }
                            }
                        }

                        result.state.insert("DB_HOST".into(), endpoint.clone());
                        result
                            .state
                            .insert("POSTGRES_HOST".into(), endpoint.clone());
                        result.state.insert("DB_STATUS".into(), "available".into());
                        result
                            .deployment_annotations
                            .insert("deckwatch.io/aws-rds-endpoint".into(), endpoint);
                    }
                    result.state.insert("DB_PORT".into(), port.clone());
                    result.state.insert("POSTGRES_PORT".into(), port);
                    result.state.insert("DB_ENGINE".into(), engine.clone());
                    result.state.insert("DB_NAME".into(), db_name.clone());
                    result.state.insert("POSTGRES_DB".into(), db_name.clone());
                    result.state.insert("POSTGRES_USER".into(), db_user);
                    if iam_auth {
                        result.state.insert("DB_IAM_AUTH".into(), "true".into());
                    }
                    result
                        .deployment_annotations
                        .insert("deckwatch.io/aws-rds-engine".into(), engine.clone());
                    result
                        .deployment_annotations
                        .insert("deckwatch.io/aws-rds-db-name".into(), db_name.clone());
                    result.deployment_annotations.extend(rds_apply_annotations(
                        &req.application_name,
                        &identifier,
                        &engine,
                        &instance_class,
                        &db_name,
                        iam_auth,
                        &role_name,
                    ));
                }
                Err(e) => {
                    result.errors.push(format!("RDS provisioning error: {e}"));
                }
            }
        }
        "s3" => {
            let bucket_name = req.fields.get("bucket_name").cloned().unwrap_or_default();
            let region = req
                .fields
                .get("region")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| creds.region.clone());

            let bucket_prefix = config::get("BUCKET_PREFIX")
                .ok()
                .flatten()
                .unwrap_or_default();
            let full_bucket = format!("{}{}", bucket_prefix, bucket_name);

            let cfg = S3Config {
                bucket_name: bucket_name.clone(),
                region: region.clone(),
                versioning: false,
                public_access_block: true,
                lifecycle_days: None,
            };

            match s3::ensure_bucket(&cfg, &full_bucket, &creds) {
                Ok(()) => {
                    result.state.insert("S3_BUCKET".into(), full_bucket.clone());
                    result.state.insert("S3_REGION".into(), region.clone());
                    result.state.insert("AWS_REGION".into(), region.clone());
                    // Stamp the bucket name and region as deployment annotations
                    // so they're visible via `kubectl get deployment -o yaml`.
                    result
                        .deployment_annotations
                        .insert("deckwatch.io/aws-s3-bucket".into(), full_bucket);
                    result
                        .deployment_annotations
                        .insert("deckwatch.io/aws-s3-region".into(), region);
                }
                Err(e) => {
                    result.errors.push(format!("S3 provisioning error: {e}"));
                }
            }
        }
        "sqs" => {
            let queue_name = req
                .fields
                .get("queue_name")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| default_sqs_queue_name(&req.namespace, &req.application_name));
            let fifo = req
                .fields
                .get("fifo")
                .map(|v| matches!(v.as_str(), "true" | "yes" | "1"))
                .unwrap_or(false);
            let visibility_timeout = req
                .fields
                .get("visibility_timeout")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(30);
            let retention_days = req
                .fields
                .get("retention_days")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(4);

            let cfg = SqsConfig {
                queue_name,
                fifo,
                visibility_timeout,
                retention_days,
            };

            match sqs::ensure_queue(&cfg, &creds) {
                Ok(info) => {
                    let name = info
                        .queue_arn
                        .split(':')
                        .next_back()
                        .unwrap_or("")
                        .to_string();
                    result.state.insert("QUEUE_URL".into(), info.queue_url);
                    result.state.insert("QUEUE_NAME".into(), name);
                }
                Err(e) => {
                    result.errors.push(format!("SQS provisioning error: {e}"));
                }
            }
        }
        "secretsmanager" => {
            let secret_name = req
                .fields
                .get("secret_name")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| default_secret_name(&req.namespace, &req.application_name));
            let desc = format!(
                "Managed by deckwatch for {}/{}",
                req.namespace, req.application_name
            );
            match secretsmanager::ensure_secret(&secret_name, &desc, &creds) {
                Ok(arn) => {
                    result.state.insert("SM_SECRET_ARN".into(), arn);
                    result.state.insert("SM_SECRET_NAME".into(), secret_name);
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Secrets Manager provisioning error: {e}"));
                }
            }
        }
        other => {
            result.errors.push(format!("unknown resource_id: {other}"));
        }
    }

    Ok(Json(result))
}

/// Clean up provisioned resources before deckwatch removes the DB record.
///
/// - **RDS**: disables deletion protection, optionally takes a final snapshot
///   (default: yes), then deletes the instance. Set `RDS_SKIP_FINAL_SNAPSHOT=true`
///   in plugin config to skip the snapshot.
/// - **S3**: leaves the bucket intact — non-empty buckets cannot be deleted without
///   enumerating and removing all objects. Deckwatch records are removed; the bucket
///   remains in AWS and can be cleaned up manually or via a lifecycle rule.
#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn deprovision(
    Json(req): Json<ResourceDeprovisionRequest>,
) -> FnResult<Json<ResourceDeprovisionResult>> {
    let mut result = ResourceDeprovisionResult::default();

    let creds = match AwsCredentials::from_config() {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("credentials error: {e}"));
            result.message = "Deprovisioning skipped — credentials unavailable.".into();
            return Ok(Json(result));
        }
    };

    let skip_snapshot = config::get("RDS_SKIP_FINAL_SNAPSHOT")
        .ok()
        .flatten()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    match req.resource_id.as_str() {
        "rds" => {
            // Derive the identifier — same logic as provision(): from state, then
            // from fields, then fall back to the default naming convention.
            let identifier = req
                .state
                .get("DB_IDENTIFIER")
                .or_else(|| req.fields.get("identifier"))
                .cloned()
                .unwrap_or_else(|| format!("{}-{}-db", req.namespace, req.application_name));

            let snapshot_msg = if skip_snapshot {
                "no final snapshot (RDS_SKIP_FINAL_SNAPSHOT=true)".to_string()
            } else {
                format!("final snapshot: {identifier}-final")
            };

            match rds::delete_instance(&identifier, skip_snapshot, &creds) {
                Ok(()) => {
                    result.message =
                        format!("RDS instance '{identifier}' deleted ({snapshot_msg}).");
                }
                Err(e) => {
                    result.errors.push(format!("delete_instance failed: {e}"));
                    result.message = format!(
                        "RDS instance '{identifier}' could not be deleted — manual cleanup required."
                    );
                }
            }
        }
        "s3" => {
            // S3 buckets with objects cannot be deleted without listing and removing
            // every object. We intentionally leave the bucket in place and tell the
            // operator what to do.
            let bucket = req
                .state
                .get("S3_BUCKET")
                .or_else(|| req.fields.get("bucket_name"))
                .cloned()
                .unwrap_or_default();

            result.message = format!(
                "S3 bucket '{bucket}' was NOT deleted — non-empty buckets must be \
                 emptied manually before deletion. Use the AWS console, CLI \
                 (`aws s3 rm s3://{bucket} --recursive`), or configure a bucket \
                 lifecycle rule to expire objects."
            );
        }
        "sqs" => {
            let queue_url = req.state.get("QUEUE_URL").cloned().unwrap_or_default();

            if queue_url.is_empty() {
                result.message =
                    "SQS queue URL not found in provisioned state — cannot delete.".into();
            } else {
                match sqs::delete_queue(&queue_url, &creds) {
                    Ok(()) => {
                        result.message = format!(
                            "SQS queue '{queue_url}' deleted. Note: the queue name cannot be \
                             reused for 60 seconds after deletion."
                        );
                    }
                    Err(e) => {
                        result.errors.push(format!("SQS DeleteQueue failed: {e}"));
                        result.message = format!(
                            "SQS queue '{queue_url}' could not be deleted — manual cleanup required."
                        );
                    }
                }
            }
        }
        "secretsmanager" => {
            let secret_name = req
                .state
                .get("SM_SECRET_NAME")
                .or_else(|| req.fields.get("secret_name"))
                .cloned()
                .unwrap_or_else(|| format!("{}/{}", req.namespace, req.application_name));

            match secretsmanager::schedule_delete_secret(&secret_name, 30, &creds) {
                Ok(deletion_date) => {
                    result.message = format!(
                        "Secret '{secret_name}' scheduled for deletion on {deletion_date}. \
                         It can be restored from the AWS console within the 30-day recovery window."
                    );
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Secrets Manager DeleteSecret failed: {e}"));
                    result.message = format!(
                        "Secret '{secret_name}' could not be scheduled for deletion — manual cleanup required."
                    );
                }
            }
        }
        other => {
            result.errors.push(format!("unknown resource_id: {other}"));
        }
    }

    Ok(Json(result))
}

/// Provision AWS resources and return env vars / Kubernetes resources for the
/// target deployment. Called by deckwatch on every create/update event.
#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn apply(Json(ctx): Json<PluginContext>) -> FnResult<Json<PluginResult>> {
    let creds = match AwsCredentials::from_config() {
        Ok(c) => c,
        Err(e) => {
            log!(
                LogLevel::Error,
                "deckwatch-plugin-aws: credentials error: {e}"
            );
            return Ok(Json(apply_inner(&ctx, "")));
        }
    };

    let bucket_prefix = config::get("BUCKET_PREFIX")
        .ok()
        .flatten()
        .unwrap_or_default();
    let result = apply_with_aws(&ctx, &creds, &bucket_prefix);
    Ok(Json(result))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ctx(annotations: &[(&str, &str)]) -> PluginContext {
        PluginContext {
            namespace: "production".into(),
            deployment_name: "my-app".into(),
            annotations: annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            labels: HashMap::new(),
            plugin_outputs: HashMap::new(),
            provisioned_resources: HashMap::new(),
        }
    }

    fn ctx_with_labels(annotations: &[(&str, &str)], labels: &[(&str, &str)]) -> PluginContext {
        PluginContext {
            namespace: "production".into(),
            deployment_name: "my-app".into(),
            annotations: annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            plugin_outputs: HashMap::new(),
            provisioned_resources: HashMap::new(),
        }
    }

    fn find_env<'a>(result: &'a PluginResult, name: &str) -> Option<&'a str> {
        result
            .env_vars
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.value.as_str())
    }

    // 1. All annotations absent — plugin must return an empty result.
    #[test]
    fn no_annotations_returns_empty() {
        let result = apply_inner(&ctx(&[]), "");
        assert!(result.env_vars.is_empty());
        assert!(result.kubernetes_resources.is_empty());
        assert!(result.service_account_name.is_none());
        assert!(result.wants_service_account.is_none());
    }

    // 2. Master opt-in with no sub-resources: no DB or S3 env vars and no SA
    //    (the SA is only requested after ensure_role succeeds).
    #[test]
    fn aws_enabled_alone_no_rds_no_s3() {
        let result = apply_inner(&ctx(&[("aws.deckwatch.io/enabled", "true")]), "");
        assert!(
            find_env(&result, "DB_PORT").is_none(),
            "no DB env vars expected"
        );
        assert!(
            find_env(&result, "S3_BUCKET").is_none(),
            "no S3 env vars expected"
        );
        assert!(
            result.wants_service_account.is_none(),
            "SA must NOT be requested in apply_inner — only after successful IAM role creation"
        );
        assert!(
            result.kubernetes_resources.is_empty(),
            "SA must not be in kubernetes_resources"
        );
    }

    // 3. RDS enabled → static DB env vars injected.
    #[test]
    fn rds_enabled_sets_db_env_vars() {
        let result = apply_inner(
            &ctx(&[
                ("rds.deckwatch.io/enabled", "true"),
                ("rds.deckwatch.io/engine", "postgres"),
                ("rds.deckwatch.io/db-name", "mydb"),
            ]),
            "",
        );
        assert_eq!(find_env(&result, "DB_PORT"), Some("5432"));
        assert_eq!(find_env(&result, "DB_NAME"), Some("mydb"));
        assert_eq!(find_env(&result, "DB_ENGINE"), Some("postgres"));
    }

    // 4. S3 enabled → S3_BUCKET (with prefix) and S3_REGION injected.
    #[test]
    fn s3_enabled_sets_s3_env_vars() {
        let result = apply_inner(
            &ctx(&[
                ("s3.deckwatch.io/enabled", "true"),
                ("s3.deckwatch.io/bucket-name", "assets"),
                ("s3.deckwatch.io/region", "us-west-2"),
            ]),
            "myorg-",
        );
        assert_eq!(find_env(&result, "S3_BUCKET"), Some("myorg-assets"));
        assert_eq!(find_env(&result, "S3_REGION"), Some("us-west-2"));
    }

    // 5. Both enabled → all env vars present.
    #[test]
    fn both_enabled_all_env_vars() {
        let result = apply_inner(
            &ctx(&[
                ("rds.deckwatch.io/enabled", "true"),
                ("rds.deckwatch.io/engine", "postgres"),
                ("s3.deckwatch.io/enabled", "true"),
                ("s3.deckwatch.io/bucket-name", "data"),
            ]),
            "",
        );
        assert!(find_env(&result, "DB_PORT").is_some());
        assert!(find_env(&result, "DB_ENGINE").is_some());
        assert!(find_env(&result, "S3_BUCKET").is_some());
        assert!(find_env(&result, "S3_REGION").is_some());
    }

    // 6. IAM auth flag set → DB_IAM_AUTH=true, no DB_PASSWORD.
    #[test]
    fn rds_iam_auth_sets_flag() {
        let result = apply_inner(
            &ctx(&[
                ("rds.deckwatch.io/enabled", "true"),
                ("rds.deckwatch.io/iam-auth", "true"),
            ]),
            "",
        );
        assert_eq!(find_env(&result, "DB_IAM_AUTH"), Some("true"));
        assert!(
            find_env(&result, "DB_PASSWORD").is_none(),
            "DB_PASSWORD must not be injected with IAM auth"
        );
    }

    // 7. BUCKET_PREFIX is applied to the bucket name.
    #[test]
    fn s3_prefix_applied() {
        let result = apply_inner(
            &ctx(&[
                ("s3.deckwatch.io/enabled", "true"),
                ("s3.deckwatch.io/bucket-name", "assets"),
            ]),
            "myorg-",
        );
        assert_eq!(find_env(&result, "S3_BUCKET"), Some("myorg-assets"));
    }

    // 8. role-name defaults to <namespace>-<app_name>-role.
    //    When no app label is set, app_name falls back to deployment_name.
    #[test]
    fn role_name_defaults() {
        let c = ctx(&[("aws.deckwatch.io/enabled", "true")]);
        let cfg = AwsConfig::from_context(&c);
        assert_eq!(cfg.role_name, "production-my-app-role");
        assert_eq!(cfg.app_name, "my-app");
    }

    // 8b. app_name is derived from the app.kubernetes.io/name label when set,
    //     so multiple deployments of the same app share one IAM role and SA.
    #[test]
    fn role_name_uses_app_label_when_set() {
        let c = ctx_with_labels(
            &[("aws.deckwatch.io/enabled", "true")],
            &[("app.kubernetes.io/name", "my-service")],
        );
        let cfg = AwsConfig::from_context(&c);
        assert_eq!(cfg.app_name, "my-service");
        assert_eq!(cfg.role_name, "production-my-service-role");
    }

    // 8c. aws.deckwatch.io/app-name annotation overrides label.
    #[test]
    fn role_name_uses_annotation_override() {
        let c = ctx_with_labels(
            &[
                ("aws.deckwatch.io/enabled", "true"),
                ("aws.deckwatch.io/app-name", "shared-app"),
            ],
            &[("app.kubernetes.io/name", "my-service")],
        );
        let cfg = AwsConfig::from_context(&c);
        assert_eq!(cfg.app_name, "shared-app");
        assert_eq!(cfg.role_name, "production-shared-app-role");
    }

    // 8d. SA name is keyed on app_name, not deployment_name.
    #[test]
    fn sa_name_keyed_on_app_name() {
        let c = ctx_with_labels(
            &[("aws.deckwatch.io/enabled", "true")],
            &[("app", "backend")],
        );
        let cfg = AwsConfig::from_context(&c);
        assert_eq!(workload_sa_name(&cfg.app_name), "backend-aws-sa");
    }

    // 9. RDS identifier defaults to <namespace>-<deployment>-db (≤ 63 chars).
    #[test]
    fn rds_identifier_defaults() {
        let c = ctx(&[("rds.deckwatch.io/enabled", "true")]);
        let cfg = AwsConfig::from_context(&c);
        let rds = cfg.rds.unwrap();
        assert_eq!(rds.identifier, "production-my-app-db");
        assert!(rds.identifier.len() <= 63, "identifier exceeds 63 chars");
    }

    // 10. Snapshot schedule and backup-role-arn annotations are parsed correctly.
    #[test]
    fn snapshot_config_parsed() {
        let c = ctx(&[
            ("rds.deckwatch.io/enabled", "true"),
            ("rds.deckwatch.io/snapshot-schedule", "cron(0 3 * * ? *)"),
            ("rds.deckwatch.io/snapshot-retention", "14"),
            (
                "rds.deckwatch.io/backup-role-arn",
                "arn:aws:iam::123456789012:role/backup-role",
            ),
        ]);
        let cfg = AwsConfig::from_context(&c);
        let rds = cfg.rds.unwrap();
        assert_eq!(rds.snapshot_schedule.as_deref(), Some("cron(0 3 * * ? *)"));
        assert_eq!(rds.snapshot_retention, 14);
        assert_eq!(
            rds.backup_role_arn,
            "arn:aws:iam::123456789012:role/backup-role"
        );
    }

    // 11. apply_inner does NOT request a ServiceAccount — that only happens after
    //     ensure_role() succeeds in apply_with_aws. This prevents a pod from
    //     binding to an SA with no IRSA role when IAM calls fail.
    #[test]
    fn service_account_not_in_apply_inner() {
        let result = apply_inner(&ctx(&[("aws.deckwatch.io/enabled", "true")]), "");
        assert!(
            result.wants_service_account.is_none(),
            "apply_inner must NOT set wants_service_account — only apply_with_aws does after ensure_role succeeds"
        );
        assert!(
            result.service_account_name.is_none(),
            "service_account_name must NOT be set in apply_inner"
        );
        assert!(
            result.kubernetes_resources.is_empty(),
            "apply_inner must NOT emit an SA kubernetes_resource"
        );
    }

    // 11b. The annotations provision() stamps make apply() resolve the same
    //      RDS instance, IAM role, ServiceAccount, and DB user — not the
    //      <namespace>-<deployment> defaults, which would create duplicates.
    #[test]
    fn provision_annotations_round_trip_through_apply() {
        let anns = rds_apply_annotations(
            "radiation-db",
            "rad-radiation-db",
            "postgres",
            "db.t3.micro",
            "radiation",
            true,
            "rad-radiation-db-rds",
        );
        let pairs: Vec<(&str, &str)> = anns.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let c = ctx_with_labels(&pairs, &[("app", "some-other-label")]);
        let cfg = AwsConfig::from_context(&c);

        assert!(cfg.enabled);
        assert_eq!(cfg.app_name, "radiation-db");
        assert_eq!(cfg.role_name, "rad-radiation-db-rds");
        assert_eq!(workload_sa_name(&cfg.app_name), "radiation-db-aws-sa");
        let rds = cfg.rds.expect("rds must be enabled");
        assert_eq!(rds.identifier, "rad-radiation-db");
        assert_eq!(rds.db_name, "radiation");
        assert!(rds.iam_auth);

        let result = apply_inner(&c, "");
        assert_eq!(find_env(&result, "POSTGRES_USER"), Some("radiation-db"));
        assert_eq!(find_env(&result, "DB_NAME"), Some("radiation"));
    }

    // 12. MySQL engine → DB_PORT=3306.
    #[test]
    fn mysql_port_3306() {
        let result = apply_inner(
            &ctx(&[
                ("rds.deckwatch.io/enabled", "true"),
                ("rds.deckwatch.io/engine", "mysql"),
            ]),
            "",
        );
        assert_eq!(find_env(&result, "DB_PORT"), Some("3306"));
    }

    // 13. outputs["role_arn"] is always present (empty placeholder on host target).
    #[test]
    fn outputs_contains_role_arn_placeholder() {
        let result = apply_inner(&ctx(&[("aws.deckwatch.io/enabled", "true")]), "");
        assert!(
            result.outputs.contains_key("role_arn"),
            "outputs must always contain 'role_arn'"
        );
    }

    // 14. rds_resource() declares the expected fields — catches metadata() regressions.
    #[test]
    fn rds_resource_has_required_fields() {
        let r = rds_resource();
        assert_eq!(r.id, "rds");
        assert!(r.singleton, "RDS must be singleton");
        assert!(
            !r.fields.is_empty(),
            "RDS resource must declare form fields"
        );
        assert!(
            !r.output_keys.is_empty(),
            "RDS resource must declare output env var keys"
        );
        assert!(
            r.output_keys.iter().any(|k| k == "DB_HOST"),
            "DB_HOST must be in output_keys"
        );
    }

    // 15. s3_resource() declares the expected fields.
    #[test]
    fn s3_resource_has_required_fields() {
        let r = s3_resource();
        assert_eq!(r.id, "s3");
        assert!(r.singleton, "S3 must be singleton");
        assert!(!r.fields.is_empty(), "S3 resource must declare form fields");
        assert!(
            !r.output_keys.is_empty(),
            "S3 resource must declare output env var keys"
        );
        assert!(
            r.output_keys.iter().any(|k| k == "S3_BUCKET"),
            "S3_BUCKET must be in output_keys"
        );
    }

    // ── New: SQS ─────────────────────────────────────────────────────────────

    #[test]
    fn sqs_enabled_sets_queue_name_env_var() {
        let result = apply_inner(
            &ctx(&[
                ("sqs.deckwatch.io/enabled", "true"),
                ("sqs.deckwatch.io/queue-name", "my-jobs"),
            ]),
            "",
        );
        assert_eq!(find_env(&result, "QUEUE_NAME"), Some("my-jobs"));
        assert!(
            result.wants_service_account.is_none(),
            "SA not requested in apply_inner"
        );
    }

    #[test]
    fn sqs_fifo_adds_suffix_to_queue_name() {
        let result = apply_inner(
            &ctx(&[
                ("sqs.deckwatch.io/enabled", "true"),
                ("sqs.deckwatch.io/queue-name", "my-jobs"),
                ("sqs.deckwatch.io/fifo", "true"),
            ]),
            "",
        );
        assert_eq!(find_env(&result, "QUEUE_NAME"), Some("my-jobs.fifo"));
    }

    #[test]
    fn sqs_defaults_queue_name() {
        let c = ctx(&[("sqs.deckwatch.io/enabled", "true")]);
        let cfg = AwsConfig::from_context(&c);
        let sqs = cfg.sqs.unwrap();
        assert_eq!(sqs.queue_name, "production-my-app-queue");
    }

    #[test]
    fn sqs_resource_has_required_fields() {
        let r = sqs_resource();
        assert_eq!(r.id, "sqs");
        assert!(r.singleton);
        assert!(r.output_keys.iter().any(|k| k == "QUEUE_URL"));
        assert!(r.output_keys.iter().any(|k| k == "QUEUE_NAME"));
    }

    // ── New: ECR ─────────────────────────────────────────────────────────────

    #[test]
    fn ecr_annotation_sets_enabled_flag() {
        let c = ctx(&[("ecr.deckwatch.io/enabled", "true")]);
        let cfg = AwsConfig::from_context(&c);
        assert!(cfg.ecr_enabled);
        assert!(cfg.enabled, "aws must be enabled when ecr is enabled");
    }

    // ── New: Secrets Manager ──────────────────────────────────────────────────

    #[test]
    fn secretsmanager_arns_parsed() {
        let c = ctx(&[(
            "secretsmanager.deckwatch.io/secret-arns",
            "arn:aws:secretsmanager:us-east-1:123:secret:a,arn:aws:secretsmanager:us-east-1:123:secret:b",
        )]);
        let cfg = AwsConfig::from_context(&c);
        let sm = cfg.secretsmanager.unwrap();
        assert_eq!(sm.secret_arns.len(), 2);
        assert!(!sm.create_secret);
    }

    #[test]
    fn secretsmanager_create_sets_sm_secret_name_env() {
        let result = apply_inner(
            &ctx(&[
                ("secretsmanager.deckwatch.io/enabled", "true"),
                ("secretsmanager.deckwatch.io/secret-name", "my-secret"),
            ]),
            "",
        );
        assert_eq!(find_env(&result, "SM_SECRET_NAME"), Some("my-secret"));
    }

    #[test]
    fn secretsmanager_resource_has_required_fields() {
        let r = secretsmanager_resource();
        assert_eq!(r.id, "secretsmanager");
        assert!(r.singleton);
        assert!(r.output_keys.iter().any(|k| k == "SM_SECRET_ARN"));
    }

    // ── IAM database user bootstrap ──────────────────────────────────────────

    #[test]
    fn bootstrap_sql_creates_iam_user_idempotently() {
        let sql = bootstrap_sql("radiation-db", "radiation").unwrap();
        assert!(sql.contains("WHERE rolname = 'radiation-db'"));
        assert!(sql.contains(r#"CREATE ROLE "radiation-db" WITH LOGIN;"#));
        assert!(sql.contains(r#"GRANT rds_iam TO "radiation-db";"#));
        assert!(sql.contains(r#"ON DATABASE "radiation" TO "radiation-db";"#));
        assert!(sql.contains(r#"ON SCHEMA public TO "radiation-db";"#));
        assert!(
            !sql.contains("PASSWORD"),
            "IAM users must not get a password"
        );
    }

    #[test]
    fn bootstrap_sql_rejects_unsafe_identifiers() {
        for user in ["", "Robert", "a\"; DROP ROLE x; --", "a'b", &"a".repeat(64)] {
            assert!(
                bootstrap_sql(user, "app").is_err(),
                "user {user:?} must be rejected"
            );
        }
        for db in ["", "1app", "app-db", "app\"x", &"a".repeat(64)] {
            assert!(
                bootstrap_sql("app", db).is_err(),
                "db {db:?} must be rejected"
            );
        }
        assert!(bootstrap_sql("my-app-2", "App_db1").is_ok());
    }

    fn sample_bootstrap() -> Vec<serde_json::Value> {
        let sql = bootstrap_sql("radiation-db", "radiation").unwrap();
        db_bootstrap_manifests(&BootstrapSpec {
            namespace: "rad",
            app: "radiation-db",
            role_arn: "arn:aws-us-gov:iam::123456789012:role/deckwatch-plugin/rad-radiation-db-rds-bootstrap",
            master_secret_arn: "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:rds!db-abc",
            region: "us-gov-west-1",
            host: "rad-radiation-db.example.rds.amazonaws.com",
            port: "5432",
            db_name: "radiation",
            sql: &sql,
            awscli_image: "amazon/aws-cli:test",
            psql_image: "postgres:test",
        })
    }

    #[test]
    fn bootstrap_emits_dedicated_irsa_sa_and_job() {
        let out = sample_bootstrap();
        assert_eq!(out.len(), 2);
        let (sa, job) = (&out[0], &out[1]);

        assert_eq!(sa["kind"], "ServiceAccount");
        assert_eq!(sa["metadata"]["name"], "radiation-db-db-bootstrap");
        assert_eq!(sa["metadata"]["namespace"], "rad");
        assert!(sa["metadata"]["annotations"]["eks.amazonaws.com/role-arn"]
            .as_str()
            .unwrap()
            .ends_with("/rad-radiation-db-rds-bootstrap"));

        assert_eq!(job["apiVersion"], "batch/v1");
        assert_eq!(job["kind"], "Job");
        let job_name = job["metadata"]["name"].as_str().unwrap();
        assert!(
            job_name.starts_with("radiation-db-db-bootstrap-"),
            "{job_name}"
        );
        let pod = &job["spec"]["template"]["spec"];
        // Runs as the bootstrap SA, never the workload SA (which must not be
        // able to read the master secret).
        assert_eq!(pod["serviceAccountName"], "radiation-db-db-bootstrap");
        assert_eq!(pod["restartPolicy"], "Never");
        assert_eq!(pod["volumes"][0]["emptyDir"]["medium"], "Memory");
        assert!(job["spec"]["ttlSecondsAfterFinished"].is_number());
    }

    #[test]
    fn bootstrap_job_wires_secret_and_connection_without_embedding_credentials() {
        let out = sample_bootstrap();
        let pod = &out[1]["spec"]["template"]["spec"];
        let env = |c: &serde_json::Value, k: &str| -> Option<String> {
            c["env"].as_array()?.iter().find(|e| e["name"] == k)?["value"]
                .as_str()
                .map(String::from)
        };

        let init = &pod["initContainers"][0];
        assert_eq!(init["image"], "amazon/aws-cli:test");
        assert_eq!(
            env(init, "MASTER_SECRET_ARN").as_deref(),
            Some("arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:rds!db-abc")
        );

        let main = &pod["containers"][0];
        assert_eq!(main["image"], "postgres:test");
        assert_eq!(
            env(main, "PGHOST").as_deref(),
            Some("rad-radiation-db.example.rds.amazonaws.com")
        );
        assert_eq!(env(main, "PGDATABASE").as_deref(), Some("radiation"));
        assert_eq!(env(main, "PGSSLMODE").as_deref(), Some("require"));
        assert!(env(main, "BOOTSTRAP_SQL")
            .unwrap()
            .contains("GRANT rds_iam"));
        assert!(
            env(main, "PGPASSWORD").is_none(),
            "password is read at runtime, never set in the spec"
        );

        // The secret is only ever referenced by ARN; nothing secret-shaped is
        // serialized into the manifests.
        let all = serde_json::to_string(&out).unwrap();
        assert!(!all.to_lowercase().contains("\"password\":"));
        assert!(!all.contains("\"kind\":\"Secret\""));
    }

    /// What the kubelet does to container command/env values: `$$` becomes
    /// `$`; `$(VAR)` would be substituted, but none of ours resolve.
    fn k8s_expand(s: &str) -> String {
        s.replace("$$", "$")
    }

    #[test]
    fn bootstrap_values_survive_kubernetes_variable_expansion() {
        let sql = bootstrap_sql("radiation-db", "radiation").unwrap();
        assert!(sql.contains("DO $$"));
        let out = sample_bootstrap();
        let pod = &out[1]["spec"]["template"]["spec"];
        let env_sql = pod["containers"][0]["env"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == "BOOTSTRAP_SQL")
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .to_string();
        // Unescaped, Postgres received "DO $" and failed with a syntax error.
        assert_eq!(k8s_expand(&env_sql), sql);

        let script = k8s_expand(pod["containers"][0]["command"][2].as_str().unwrap());
        assert!(script.contains(r#""$BOOTSTRAP_SQL""#));
        assert!(script.contains("PGPASSWORD=$(sed"));
        let init = k8s_expand(pod["initContainers"][0]["command"][2].as_str().unwrap());
        assert!(init.contains(r#""$MASTER_SECRET_ARN""#));
    }

    #[test]
    fn bootstrap_job_name_tracks_spec_and_fits_limit() {
        let a = sample_bootstrap();
        let b = sample_bootstrap();
        assert_eq!(
            a[1]["metadata"]["name"], b[1]["metadata"]["name"],
            "stable for identical spec"
        );

        let sql = bootstrap_sql("radiation-db", "radiation").unwrap();
        let changed = db_bootstrap_manifests(&BootstrapSpec {
            namespace: "rad",
            app: "radiation-db",
            role_arn: "arn:aws-us-gov:iam::123456789012:role/deckwatch-plugin/rad-radiation-db-rds-bootstrap",
            master_secret_arn: "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:rds!db-abc",
            region: "us-gov-west-1",
            host: "rad-radiation-db.example.rds.amazonaws.com",
            port: "5432",
            db_name: "radiation",
            sql: &sql,
            awscli_image: "amazon/aws-cli:test",
            psql_image: "postgres:other",
        });
        assert_ne!(
            a[1]["metadata"]["name"], changed[1]["metadata"]["name"],
            "new spec, new Job"
        );
        // The SA name is unaffected by spec changes.
        assert_eq!(a[0]["metadata"]["name"], changed[0]["metadata"]["name"]);

        let long_app = "a".repeat(53);
        let name = bootstrap_job_name(&long_app, &serde_json::json!({}));
        assert!(name.len() <= 63, "{} chars: {name}", name.len());
        assert!(!name.contains("--"));
    }
}
