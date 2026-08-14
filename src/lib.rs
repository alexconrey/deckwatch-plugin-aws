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
    ResourceProvisionRequest, ResourceProvisionResult,
};
#[cfg(target_arch = "wasm32")]
use extism_pdk::*;

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

fn workload_sa_name(deployment: &str) -> String {
    format!("{deployment}-aws-sa")
}

fn engine_port(engine: &str) -> u16 {
    match engine {
        "mysql" | "mariadb" | "aurora-mysql" => 3306,
        _ => 5432,
    }
}

// ── Config parsing ────────────────────────────────────────────────────────────

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

        let role_name = {
            let raw = ann_str(ctx, "aws.deckwatch.io/role-name");
            if raw.is_empty() {
                default_role_name(&ctx.namespace, &ctx.deployment_name)
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
                    let raw = ann_str(ctx, "rds.deckwatch.io/subnet-group");
                    if raw.is_empty() {
                        None
                    } else {
                        Some(raw)
                    }
                },
                security_groups: {
                    let raw = ann_str(ctx, "rds.deckwatch.io/security-groups");
                    if raw.is_empty() {
                        vec![]
                    } else {
                        raw.split(',').map(|s| s.trim().to_string()).collect()
                    }
                },
                iam_auth: ann_bool(ctx, "rds.deckwatch.io/iam-auth", false),
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
            role_name,
            rds,
            s3,
            sqs,
            ecr_enabled,
            secretsmanager,
        }
    }
}

// ── ServiceAccount YAML (pure) ────────────────────────────────────────────────

/// Build a Kubernetes `ServiceAccount` manifest with an IRSA role annotation.
///
/// `role_arn` is empty in the static/host path and filled in by the WASM path
/// after creating the actual IAM role.
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
    let sa = workload_sa_name(&ctx.deployment_name);

    // ── ServiceAccount ────────────────────────────────────────────────────────
    // The role ARN is unknown statically; the WASM path overwrites this SA with
    // the real ARN after ensure_role() returns.
    result
        .kubernetes_resources
        .push(service_account_yaml(&sa, "", &ctx.namespace));
    result.service_account_name = Some(sa.clone());

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
            .push(EnvVarSpec::value("DB_NAME", &rds.db_name));
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
    result.outputs.insert("role_arn".into(), String::new());
    result.outputs.insert("service_account_name".into(), sa);

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

    let sa = workload_sa_name(&ctx.deployment_name);

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
            Ok(endpoint) => {
                if let Err(e) = iam::attach_rds_policy(
                    &cfg.role_name,
                    &rds_cfg.identifier,
                    &creds.region,
                    creds,
                ) {
                    log!(
                        LogLevel::Warn,
                        "deckwatch-plugin-aws: attach_rds_policy: {e}"
                    );
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
                endpoint
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

    result.kubernetes_resources.clear();
    result
        .kubernetes_resources
        .push(service_account_yaml(&sa, &role_arn, &ctx.namespace));

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
        ],
        output_keys: vec![
            "DB_HOST".into(),
            "DB_PORT".into(),
            "DB_ENGINE".into(),
            "DB_NAME".into(),
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

            let cfg = RdsConfig {
                identifier,
                engine: engine.clone(),
                instance_class,
                allocated_storage: "20".to_string(),
                db_name: db_name.clone(),
                multi_az: false,
                subnet_group: None,
                security_groups: vec![],
                iam_auth: false,
                snapshot_schedule: None,
                snapshot_retention: 7,
                backup_role_arn: String::new(),
                region: creds.region.clone(),
            };

            match rds::ensure_instance(&cfg, &creds) {
                Ok(endpoint) => {
                    let port = engine_port(&engine).to_string();
                    if endpoint.is_empty() {
                        result
                            .state
                            .insert("DB_STATUS".into(), "provisioning".into());
                    } else {
                        result.state.insert("DB_HOST".into(), endpoint.clone());
                        result.state.insert("DB_STATUS".into(), "available".into());
                        result
                            .deployment_annotations
                            .insert("deckwatch.io/aws-rds-endpoint".into(), endpoint);
                    }
                    result.state.insert("DB_PORT".into(), port);
                    result.state.insert("DB_ENGINE".into(), engine.clone());
                    result.state.insert("DB_NAME".into(), db_name.clone());
                    result
                        .deployment_annotations
                        .insert("deckwatch.io/aws-rds-engine".into(), engine);
                    result
                        .deployment_annotations
                        .insert("deckwatch.io/aws-rds-db-name".into(), db_name);
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
                    let name = info.queue_arn.split(':').last().unwrap_or("").to_string();
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
    }

    // 2. Master opt-in with no sub-resources: no DB or S3 env vars but SA is present.
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
        assert!(result.service_account_name.is_some(), "SA must be created");
        assert!(
            !result.kubernetes_resources.is_empty(),
            "SA resource must be emitted"
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

    // 8. role-name defaults to <namespace>-<deployment>-role.
    #[test]
    fn role_name_defaults() {
        let c = ctx(&[("aws.deckwatch.io/enabled", "true")]);
        let cfg = AwsConfig::from_context(&c);
        assert_eq!(cfg.role_name, "production-my-app-role");
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

    // 11. When any AWS resource is enabled, a ServiceAccount is in kubernetes_resources.
    #[test]
    fn service_account_in_kubernetes_resources() {
        let result = apply_inner(&ctx(&[("aws.deckwatch.io/enabled", "true")]), "");
        assert!(
            !result.kubernetes_resources.is_empty(),
            "kubernetes_resources must be non-empty"
        );
        let sa = &result.kubernetes_resources[0];
        assert_eq!(
            sa["kind"].as_str(),
            Some("ServiceAccount"),
            "first resource must be ServiceAccount"
        );
        assert!(
            result.service_account_name.is_some(),
            "service_account_name must be set"
        );
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
        assert!(result.service_account_name.is_some());
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
}
