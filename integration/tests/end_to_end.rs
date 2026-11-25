//! End-to-end: the compiled `plugin.wasm`, run by a stock extism host, against
//! a moto AWS emulator.
//!
//! Each test drives the plugin's real WASM exports (`provision`, `apply`) with
//! the same JSON deckwatch sends, then reads AWS state back through the
//! official AWS SDK — an independent client, so a bug in the plugin's own
//! request building or SigV4 code can't make a test pass by accident.
//!
//! The extism manifest only allows HTTP to the moto host. Any request the
//! plugin tried to send to real `*.amazonaws.com` is rejected by the sandbox
//! and fails the test.
//!
//! Environment:
//! - `MOTO_ENDPOINT` — moto server URL (default `http://localhost:5000`)
//! - `PLUGIN_WASM`   — path to the built plugin (default `../dist/plugin.wasm`)
//!
//! Tests use unique application names so they can share one moto server and
//! run in parallel.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_iam::types::Role;
use deckwatch_plugin_sdk::{
    PluginContext, PluginResult, ResourceDeprovisionRequest, ResourceDeprovisionResult,
    ResourceProvisionRequest, ResourceProvisionResult,
};
use extism::{Manifest, Plugin, Wasm};
use serde_json::Value;

const ACCOUNT_KEY: &str = "testing";
const OIDC_PROVIDER_ARN: &str =
    "arn:aws:iam::123456789012:oidc-provider/oidc.eks.example.com/id/TEST";

fn moto_endpoint() -> String {
    std::env::var("MOTO_ENDPOINT").unwrap_or_else(|_| "http://localhost:5000".into())
}

fn moto_host() -> String {
    let ep = moto_endpoint();
    let authority = ep.split_once("://").map(|(_, a)| a).unwrap_or(&ep);
    authority
        .split(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .to_string()
}

/// Suffix unique to this test process. Names include it so reruns against a
/// long-lived moto server never collide with state left by earlier runs.
fn run_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        format!("{:06x}", ms % 0xff_ffff)
    })
}

/// `<base>-<run_id>`, leaked so tests can keep using `&str` names.
fn unique(base: &str) -> &'static str {
    Box::leak(format!("{base}-{}", run_id()).into_boxed_str())
}

// ── Plugin harness ────────────────────────────────────────────────────────────

/// Load `plugin.wasm` with the config deckwatch would inject, pointed at moto.
fn load_plugin(region: &str, extra: &[(&str, &str)]) -> Plugin {
    let wasm_path = std::env::var("PLUGIN_WASM").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../dist/plugin.wasm").to_string()
    });
    assert!(
        std::path::Path::new(&wasm_path).exists(),
        "plugin not found at {wasm_path} — run `make build` in the repo root first"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let endpoint = moto_endpoint();

    let mut config: Vec<(String, String)> = [
        ("AWS_ACCESS_KEY_ID", ACCOUNT_KEY),
        ("AWS_SECRET_ACCESS_KEY", ACCOUNT_KEY),
        ("AWS_REGION", region),
        ("AWS_ENDPOINT_URL", endpoint.as_str()),
        ("CURRENT_TIMESTAMP", now.as_str()),
        ("OIDC_PROVIDER_ARN", OIDC_PROVIDER_ARN),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    // Later entries win, so callers can override the defaults above.
    config.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));

    let manifest = Manifest::new([Wasm::file(&wasm_path)])
        .with_allowed_host(moto_host())
        .with_config(config.into_iter());
    Plugin::new(&manifest, [], false).expect("load plugin.wasm")
}

fn call_provision(plugin: &mut Plugin, req: &ResourceProvisionRequest) -> ResourceProvisionResult {
    let input = serde_json::to_string(req).unwrap();
    let out = plugin
        .call::<&str, &str>("provision", &input)
        .expect("provision export");
    serde_json::from_str(out).expect("provision result JSON")
}

fn call_apply(plugin: &mut Plugin, ctx: &PluginContext) -> PluginResult {
    let input = serde_json::to_string(ctx).unwrap();
    let out = plugin
        .call::<&str, &str>("apply", &input)
        .expect("apply export");
    serde_json::from_str(out).expect("apply result JSON")
}

fn call_deprovision(
    plugin: &mut Plugin,
    req: &ResourceDeprovisionRequest,
) -> ResourceDeprovisionResult {
    let input = serde_json::to_string(req).unwrap();
    let out = plugin
        .call::<&str, &str>("deprovision", &input)
        .expect("deprovision export");
    serde_json::from_str(out).expect("deprovision result JSON")
}

/// The request deckwatch sends to deprovision a resource it provisioned:
/// the original form fields plus the state provision() returned.
fn deprovision_request(
    provision_req: &ResourceProvisionRequest,
    provisioned: &ResourceProvisionResult,
) -> ResourceDeprovisionRequest {
    ResourceDeprovisionRequest {
        application_name: provision_req.application_name.clone(),
        namespace: provision_req.namespace.clone(),
        resource_id: provision_req.resource_id.clone(),
        state: provisioned.state.clone(),
        fields: provision_req.fields.clone(),
        ..Default::default()
    }
}

fn resource_request(
    app: &str,
    namespace: &str,
    resource_id: &str,
    fields: &[(&str, &str)],
) -> ResourceProvisionRequest {
    ResourceProvisionRequest {
        application_name: app.into(),
        namespace: namespace.into(),
        resource_id: resource_id.into(),
        fields: fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        ..Default::default()
    }
}

/// Inline policy names on a role, or None if the role doesn't exist.
async fn role_policies(iam: &aws_sdk_iam::Client, role: &str) -> Option<Vec<String>> {
    match iam.list_role_policies().role_name(role).send().await {
        Ok(out) => Some(out.policy_names().to_vec()),
        Err(e) if format!("{e:?}").contains("NoSuchEntity") => None,
        Err(e) => panic!("ListRolePolicies {role}: {e:?}"),
    }
}

fn s3_request(app: &str, namespace: &str, bucket: &str, region: &str) -> ResourceProvisionRequest {
    ResourceProvisionRequest {
        application_name: app.into(),
        namespace: namespace.into(),
        resource_id: "s3".into(),
        fields: HashMap::from([
            ("bucket_name".into(), bucket.into()),
            ("region".into(), region.into()),
        ]),
        ..Default::default()
    }
}

// ── AWS SDK clients (independent verification) ────────────────────────────────

async fn sdk_config(region: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(moto_endpoint())
        .region(aws_config::Region::new(region.to_string()))
        .credentials_provider(aws_sdk_iam::config::Credentials::new(
            ACCOUNT_KEY,
            ACCOUNT_KEY,
            None,
            None,
            "integration-test",
        ))
        .load()
        .await
}

async fn iam_client(region: &str) -> aws_sdk_iam::Client {
    aws_sdk_iam::Client::new(&sdk_config(region).await)
}

async fn backup_client(region: &str) -> aws_sdk_backup::Client {
    aws_sdk_backup::Client::new(&sdk_config(region).await)
}

/// Tag map from (key, value) pairs.
fn tag_map<K: AsRef<str>, V: AsRef<str>>(
    pairs: impl IntoIterator<Item = (K, V)>,
) -> HashMap<String, String> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
        .collect()
}

async fn rds_client(region: &str) -> aws_sdk_rds::Client {
    aws_sdk_rds::Client::new(&sdk_config(region).await)
}

async fn db_instance(rds: &aws_sdk_rds::Client, id: &str) -> aws_sdk_rds::types::DbInstance {
    rds.describe_db_instances()
        .db_instance_identifier(id)
        .send()
        .await
        .unwrap_or_else(|e| panic!("RDS instance {id} must exist: {e:?}"))
        .db_instances()
        .first()
        .cloned()
        .expect("instance in response")
}

async fn sqs_client(region: &str) -> aws_sdk_sqs::Client {
    aws_sdk_sqs::Client::new(&sdk_config(region).await)
}

async fn secrets_client(region: &str) -> aws_sdk_secretsmanager::Client {
    aws_sdk_secretsmanager::Client::new(&sdk_config(region).await)
}

async fn s3_client(region: &str) -> aws_sdk_s3::Client {
    let conf = aws_sdk_s3::config::Builder::from(&sdk_config(region).await)
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(conf)
}

async fn get_role(iam: &aws_sdk_iam::Client, name: &str) -> Role {
    iam.get_role()
        .role_name(name)
        .send()
        .await
        .unwrap_or_else(|e| panic!("role {name} must exist: {e:?}"))
        .role
        .expect("role in response")
}

/// Inline policy document for a role, decoded to JSON.
async fn inline_policy(iam: &aws_sdk_iam::Client, role: &str, policy: &str) -> Value {
    let doc = iam
        .get_role_policy()
        .role_name(role)
        .policy_name(policy)
        .send()
        .await
        .unwrap_or_else(|e| panic!("inline policy {policy} on {role} must exist: {e:?}"))
        .policy_document;
    // IAM returns the document URL-encoded; moto may return it decoded.
    let decoded = percent_decode(&doc);
    serde_json::from_str(&decoded).unwrap_or_else(|e| panic!("policy JSON: {e}: {decoded}"))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn policy_resources(doc: &Value) -> Vec<String> {
    doc["Statement"]
        .as_array()
        .expect("Statement array")
        .iter()
        .map(|s| s["Resource"].as_str().expect("string Resource").to_string())
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Mirrors a production app: RDS provisioning already created the app role with
/// only an rds-db:connect policy, then S3 is provisioned for the app.
///
/// Before the fix the role never received an S3 policy. Now provision("s3")
/// must create the bucket, attach a GovCloud-partition S3 policy to that same
/// role without disturbing the RDS policy, emit the IRSA ServiceAccount, and
/// stamp annotations that make apply() keep it in place on every reconcile.
#[tokio::test]
async fn govcloud_s3_provision_grants_existing_app_role() {
    let region = "us-gov-west-1";
    let (ns, app, bucket) = ("atlas-it", unique("atlas-gov"), unique("acme-atlas-gov"));
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;

    // Pre-existing state left by RDS provisioning.
    iam.create_role()
        .role_name(&role_name)
        .path("/deckwatch-plugin/")
        .assume_role_policy_document(r#"{"Version":"2012-10-17","Statement":[]}"#)
        .send()
        .await
        .expect("seed role");
    iam.put_role_policy()
        .role_name(&role_name)
        .policy_name("deckwatch-rds-connect")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws-us-gov:rds-db:us-gov-west-1:123456789012:dbuser:db-TEST/atlas"}]}"#)
        .send()
        .await
        .expect("seed rds policy");

    let mut plugin = load_plugin(region, &[]);
    let result = call_provision(&mut plugin, &s3_request(app, ns, bucket, region));
    assert!(
        result.errors.is_empty(),
        "provision errors: {:?}",
        result.errors
    );
    assert!(
        result.warnings.is_empty(),
        "provision warnings: {:?}",
        result.warnings
    );

    // Bucket exists.
    s3_client(region)
        .await
        .head_bucket()
        .bucket(bucket)
        .send()
        .await
        .unwrap_or_else(|e| panic!("bucket {bucket} must exist: {e:?}"));

    // The S3 policy landed on the app's existing role, with GovCloud ARNs.
    let s3_policy = inline_policy(&iam, &role_name, "deckwatch-s3-access").await;
    assert_eq!(
        policy_resources(&s3_policy),
        vec![
            format!("arn:aws-us-gov:s3:::{bucket}/*"),
            format!("arn:aws-us-gov:s3:::{bucket}"),
        ]
    );
    // The RDS policy is untouched.
    let rds_policy = inline_policy(&iam, &role_name, "deckwatch-rds-connect").await;
    assert_eq!(rds_policy["Statement"][0]["Action"], "rds-db:connect");

    // Trust policy is now scoped to the app's ServiceAccount via the OIDC provider.
    let role = get_role(&iam, &role_name).await;
    let trust = percent_decode(role.assume_role_policy_document().unwrap_or_default());
    assert!(
        trust.contains(&format!("system:serviceaccount:{ns}:{app}-aws-sa")),
        "trust policy must name the app SA: {trust}"
    );

    // ServiceAccount bound to that role is emitted for deckwatch to apply.
    let sa = result
        .kubernetes_resources
        .iter()
        .find(|r| r["kind"] == "ServiceAccount")
        .expect("ServiceAccount in kubernetes_resources");
    assert_eq!(sa["metadata"]["name"], format!("{app}-aws-sa"));
    assert_eq!(sa["metadata"]["namespace"], ns);
    assert_eq!(
        sa["metadata"]["annotations"]["eks.amazonaws.com/role-arn"],
        role.arn()
    );

    // State and annotations deckwatch persists.
    assert_eq!(
        result.state.get("S3_BUCKET").map(String::as_str),
        Some(bucket)
    );
    assert_eq!(
        result.state.get("S3_REGION").map(String::as_str),
        Some(region)
    );
    let ann = &result.deployment_annotations;
    assert_eq!(
        ann.get("s3.deckwatch.io/enabled").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ann.get("s3.deckwatch.io/bucket-name").map(String::as_str),
        Some(bucket)
    );
    assert_eq!(
        ann.get("s3.deckwatch.io/region").map(String::as_str),
        Some(region)
    );
    assert_eq!(ann.get("aws.deckwatch.io/role-name"), Some(&role_name));
    assert_eq!(
        ann.get("aws.deckwatch.io/app-name").map(String::as_str),
        Some(app)
    );
}

/// After provisioning, deckwatch stamps the returned annotations on the
/// deployment and calls apply() on every reconcile. apply() must resolve the
/// same role and ServiceAccount and keep the S3 policy attached — even if
/// someone removed it out-of-band.
#[tokio::test]
async fn apply_reconcile_reasserts_s3_policy_and_service_account() {
    let region = "us-gov-west-1";
    let (ns, app, bucket) = (
        "atlas-it",
        unique("atlas-reconcile"),
        unique("acme-atlas-reconcile"),
    );
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;

    let mut plugin = load_plugin(region, &[]);
    let provisioned = call_provision(&mut plugin, &s3_request(app, ns, bucket, region));
    assert!(
        provisioned.errors.is_empty(),
        "provision errors: {:?}",
        provisioned.errors
    );

    // Simulate drift: the policy is deleted out-of-band.
    iam.delete_role_policy()
        .role_name(&role_name)
        .policy_name("deckwatch-s3-access")
        .send()
        .await
        .expect("delete policy");

    let ctx = PluginContext {
        namespace: ns.into(),
        deployment_name: "backend".into(),
        annotations: provisioned.deployment_annotations.clone(),
        labels: HashMap::from([("app".into(), "backend".into())]),
        plugin_outputs: HashMap::new(),
        provisioned_resources: HashMap::new(),
        ..Default::default()
    };
    let applied = call_apply(&mut plugin, &ctx);

    let wants = applied
        .wants_service_account
        .expect("apply must request the app ServiceAccount");
    assert_eq!(wants.name, format!("{app}-aws-sa"));
    assert_eq!(wants.irsa_role_arn, get_role(&iam, &role_name).await.arn());

    let env: HashMap<_, _> = applied
        .env_vars
        .iter()
        .map(|e| (e.name.as_str(), e.value.as_str()))
        .collect();
    assert_eq!(env.get("S3_BUCKET"), Some(&bucket));

    let s3_policy = inline_policy(&iam, &role_name, "deckwatch-s3-access").await;
    assert_eq!(
        policy_resources(&s3_policy),
        vec![
            format!("arn:aws-us-gov:s3:::{bucket}/*"),
            format!("arn:aws-us-gov:s3:::{bucket}"),
        ]
    );
}

/// Commercial regions keep the `arn:aws` partition, and provisioning works
/// when no role exists yet (S3 is the app's first AWS resource).
#[tokio::test]
async fn commercial_s3_provision_creates_role_when_missing() {
    let region = "us-east-1";
    let (ns, app, bucket) = (
        "demo-it",
        unique("demo-commercial"),
        unique("demo-commercial"),
    );
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;

    let mut plugin = load_plugin(region, &[]);
    let result = call_provision(&mut plugin, &s3_request(app, ns, bucket, region));
    assert!(
        result.errors.is_empty(),
        "provision errors: {:?}",
        result.errors
    );
    assert!(
        result.warnings.is_empty(),
        "provision warnings: {:?}",
        result.warnings
    );

    let role = get_role(&iam, &role_name).await;
    assert_eq!(role.path(), "/deckwatch-plugin/");
    let s3_policy = inline_policy(&iam, &role_name, "deckwatch-s3-access").await;
    assert_eq!(
        policy_resources(&s3_policy),
        vec![
            format!("arn:aws:s3:::{bucket}/*"),
            format!("arn:aws:s3:::{bucket}")
        ]
    );
}

/// BUCKET_PREFIX is applied to the real bucket and policy, but the annotation
/// carries the unprefixed name so apply() doesn't prefix it twice.
#[tokio::test]
async fn bucket_prefix_applied_once_end_to_end() {
    let region = "us-gov-west-1";
    let (ns, app, suffix) = ("atlas-it", unique("atlas-prefix"), unique("prefixed"));
    let full = format!("acme-{suffix}");
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;

    let mut plugin = load_plugin(region, &[("BUCKET_PREFIX", "acme-")]);
    let provisioned = call_provision(&mut plugin, &s3_request(app, ns, suffix, region));
    assert!(
        provisioned.errors.is_empty(),
        "provision errors: {:?}",
        provisioned.errors
    );
    assert_eq!(provisioned.state.get("S3_BUCKET"), Some(&full));
    assert_eq!(
        provisioned
            .deployment_annotations
            .get("s3.deckwatch.io/bucket-name")
            .map(String::as_str),
        Some(suffix)
    );

    let ctx = PluginContext {
        namespace: ns.into(),
        deployment_name: "backend".into(),
        annotations: provisioned.deployment_annotations,
        labels: HashMap::new(),
        plugin_outputs: HashMap::new(),
        provisioned_resources: HashMap::new(),
        ..Default::default()
    };
    let applied = call_apply(&mut plugin, &ctx);
    let s3_env = applied.env_vars.iter().find(|e| e.name == "S3_BUCKET");
    assert_eq!(s3_env.map(|e| e.value.as_str()), Some(full.as_str()));

    let s3_policy = inline_policy(&iam, &role_name, "deckwatch-s3-access").await;
    assert_eq!(
        policy_resources(&s3_policy)[1],
        format!("arn:aws-us-gov:s3:::{full}")
    );
}

/// A deployment opting into SQS by annotation gets a queue and a
/// deckwatch-sqs-access policy on its workload role. In GovCloud the policy
/// must use the arn:aws-us-gov partition (it used to be hardcoded to arn:aws,
/// so it never matched), and must name the real account parsed from moto's
/// queue URL rather than the account-wildcard fallback.
#[tokio::test]
async fn govcloud_sqs_annotation_grants_queue_access() {
    let region = "us-gov-west-1";
    let (ns, app, queue) = ("orders-it", unique("orders"), unique("orders-events"));
    let role_name = format!("{ns}-{app}-role");
    let iam = iam_client(region).await;

    let mut plugin = load_plugin(region, &[]);
    let ctx = PluginContext {
        namespace: ns.into(),
        deployment_name: "worker".into(),
        annotations: HashMap::from([
            ("sqs.deckwatch.io/enabled".into(), "true".into()),
            ("sqs.deckwatch.io/queue-name".into(), queue.into()),
            ("aws.deckwatch.io/app-name".into(), app.into()),
        ]),
        labels: HashMap::new(),
        plugin_outputs: HashMap::new(),
        provisioned_resources: HashMap::new(),
        ..Default::default()
    };
    let applied = call_apply(&mut plugin, &ctx);

    let queue_url = applied
        .outputs
        .get("queue_url")
        .cloned()
        .unwrap_or_default();
    assert!(
        queue_url.ends_with(&format!("/{queue}")),
        "apply must output the queue URL, got {queue_url:?}"
    );
    let account = queue_url
        .rsplit('/')
        .nth(1)
        .expect("account segment in queue URL");

    let sqs_policy = inline_policy(&iam, &role_name, "deckwatch-sqs-access").await;
    assert_eq!(
        sqs_policy["Statement"][0]["Resource"],
        format!("arn:aws-us-gov:sqs:{region}:{account}:{queue}")
    );
    assert_eq!(
        applied.wants_service_account.map(|w| w.name),
        Some(format!("{app}-aws-sa"))
    );
}

/// Provisioned SQS queues used to get no IAM grant at all. Now provision()
/// attaches deckwatch-sqs-access (GovCloud partition, real account) to the app
/// role, emits the ServiceAccount, and stamps annotations for apply().
#[tokio::test]
async fn govcloud_sqs_provision_grants_queue_access() {
    let region = "us-gov-west-1";
    let (ns, app, queue) = ("billing-it", unique("billing"), unique("billing-jobs"));
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;

    let mut plugin = load_plugin(region, &[]);
    let req = resource_request(app, ns, "sqs", &[("queue_name", queue)]);
    let result = call_provision(&mut plugin, &req);
    assert!(
        result.errors.is_empty(),
        "provision errors: {:?}",
        result.errors
    );
    assert!(
        result.warnings.is_empty(),
        "provision warnings: {:?}",
        result.warnings
    );

    let queue_url = result.state.get("QUEUE_URL").cloned().unwrap_or_default();
    let account = queue_url.rsplit('/').nth(1).expect("account in queue URL");
    let policy = inline_policy(&iam, &role_name, "deckwatch-sqs-access").await;
    assert_eq!(
        policy["Statement"][0]["Resource"],
        format!("arn:aws-us-gov:sqs:{region}:{account}:{queue}")
    );
    assert_eq!(
        result.state.get("SQS_SA_NAME"),
        Some(&format!("{app}-aws-sa"))
    );
    assert!(
        result
            .kubernetes_resources
            .iter()
            .any(|r| r["kind"] == "ServiceAccount"
                && r["metadata"]["name"] == format!("{app}-aws-sa"))
    );
    let ann = &result.deployment_annotations;
    assert_eq!(
        ann.get("sqs.deckwatch.io/enabled").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ann.get("sqs.deckwatch.io/queue-name").map(String::as_str),
        Some(queue)
    );
    assert_eq!(ann.get("aws.deckwatch.io/role-name"), Some(&role_name));
}

/// Provisioned secrets now grant read access to the app role, and their
/// deprovisioning schedules recoverable deletion and cleans up the role.
#[tokio::test]
async fn secretsmanager_provision_grants_and_deprovision_cleans_up() {
    let region = "us-gov-west-1";
    let (ns, app) = ("vault-it", unique("vault"));
    let secret_name = format!("{ns}/{app}");
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;

    let mut plugin = load_plugin(region, &[]);
    let req = resource_request(app, ns, "secretsmanager", &[]);
    let provisioned = call_provision(&mut plugin, &req);
    assert!(
        provisioned.errors.is_empty(),
        "provision errors: {:?}",
        provisioned.errors
    );
    let arn = provisioned
        .state
        .get("SM_SECRET_ARN")
        .cloned()
        .expect("secret ARN");

    let policy = inline_policy(&iam, &role_name, "deckwatch-secretsmanager-access").await;
    assert_eq!(policy["Statement"][0]["Resource"], serde_json::json!([arn]));
    // The workload can write values to the secret the plugin created for it.
    assert_eq!(
        policy["Statement"][1]["Action"],
        serde_json::json!(["secretsmanager:PutSecretValue"])
    );
    assert_eq!(policy["Statement"][1]["Resource"], serde_json::json!([arn]));
    assert_eq!(
        provisioned
            .deployment_annotations
            .get("secretsmanager.deckwatch.io/owned-secret-arns"),
        Some(&arn)
    );
    assert!(
        !provisioned
            .deployment_annotations
            .contains_key("secretsmanager.deckwatch.io/enabled"),
        "grant-only: apply() must not be told to create secrets"
    );

    let removed = call_deprovision(&mut plugin, &deprovision_request(&req, &provisioned));
    assert!(
        removed.errors.is_empty(),
        "deprovision errors: {:?}",
        removed.errors
    );
    let described = secrets_client(region)
        .await
        .describe_secret()
        .secret_id(&secret_name)
        .send()
        .await
        .expect("secret is still restorable during the recovery window");
    assert!(
        described.deleted_date().is_some(),
        "deletion must be scheduled"
    );
    assert_eq!(
        role_policies(&iam, &role_name).await,
        None,
        "last resource: role deleted"
    );
}

/// The workload role is shared by every resource of an application.
/// Deprovisioning one resource removes only its policy; the role is deleted
/// with the last one. S3 data is always kept, and an empty queue is deleted.
#[tokio::test]
async fn deprovision_keeps_shared_role_until_last_resource() {
    let region = "us-gov-west-1";
    let (ns, app) = ("shop-it", unique("shop"));
    let (bucket, queue) = (unique("acme-shop-assets"), unique("shop-orders"));
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;
    let mut plugin = load_plugin(region, &[]);

    let s3_req = s3_request(app, ns, bucket, region);
    let s3_res = call_provision(&mut plugin, &s3_req);
    let sqs_req = resource_request(app, ns, "sqs", &[("queue_name", queue)]);
    let sqs_res = call_provision(&mut plugin, &sqs_req);
    assert!(s3_res.errors.is_empty() && sqs_res.errors.is_empty());
    let mut both = role_policies(&iam, &role_name).await.expect("role exists");
    both.sort();
    assert_eq!(both, vec!["deckwatch-s3-access", "deckwatch-sqs-access"]);

    // Remove S3: bucket kept, only its policy removed, role kept for SQS.
    let removed = call_deprovision(&mut plugin, &deprovision_request(&s3_req, &s3_res));
    assert!(
        removed.errors.is_empty(),
        "deprovision errors: {:?}",
        removed.errors
    );
    s3_client(region)
        .await
        .head_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("S3 data must be kept on deprovision");
    assert_eq!(
        role_policies(&iam, &role_name).await,
        Some(vec!["deckwatch-sqs-access".to_string()])
    );

    // Remove the (empty) queue: deleted, and the role goes with it.
    let removed = call_deprovision(&mut plugin, &deprovision_request(&sqs_req, &sqs_res));
    assert!(
        removed.errors.is_empty(),
        "deprovision errors: {:?}",
        removed.errors
    );
    let still_there = sqs_client(region)
        .await
        .get_queue_url()
        .queue_name(queue)
        .send()
        .await;
    assert!(still_there.is_err(), "empty queue must be deleted");
    assert_eq!(
        role_policies(&iam, &role_name).await,
        None,
        "role deleted with the last resource"
    );
    assert!(
        removed.message.contains("ServiceAccount"),
        "operator is told the ServiceAccount must be removed: {}",
        removed.message
    );
}

/// SQS messages can't be snapshotted, so a queue that still holds messages is
/// kept on deprovision, and so is the application's access to drain it.
#[tokio::test]
async fn deprovision_keeps_sqs_queue_that_still_has_messages() {
    let region = "us-gov-west-1";
    let (ns, app, queue) = ("mail-it", unique("mail"), unique("mail-outbox"));
    let role_name = format!("{ns}-{app}-rds");
    let iam = iam_client(region).await;
    let mut plugin = load_plugin(region, &[]);

    let req = resource_request(app, ns, "sqs", &[("queue_name", queue)]);
    let provisioned = call_provision(&mut plugin, &req);
    assert!(
        provisioned.errors.is_empty(),
        "provision errors: {:?}",
        provisioned.errors
    );
    let queue_url = provisioned
        .state
        .get("QUEUE_URL")
        .cloned()
        .expect("queue URL");
    let sqs = sqs_client(region).await;
    sqs.send_message()
        .queue_url(&queue_url)
        .message_body("pending")
        .send()
        .await
        .expect("send message");

    let removed = call_deprovision(&mut plugin, &deprovision_request(&req, &provisioned));
    assert!(
        removed.errors.is_empty(),
        "deprovision errors: {:?}",
        removed.errors
    );
    assert!(
        removed.message.contains("kept"),
        "message: {}",
        removed.message
    );
    sqs.get_queue_url()
        .queue_name(queue)
        .send()
        .await
        .expect("queue with messages must be kept");
    assert_eq!(
        role_policies(&iam, &role_name).await,
        Some(vec!["deckwatch-sqs-access".to_string()]),
        "access is kept so the queue can be drained"
    );
}

/// RDS's API default is 1 day of automated backups. Instances the plugin
/// creates must get the plugin's retention (14 days by default) and copy tags
/// to snapshots.
#[tokio::test]
async fn provisioned_rds_gets_14_day_backup_retention() {
    let region = "us-gov-west-1";
    let (ns, app) = ("ledger-it", unique("ledger"));
    let identifier = unique("ledger-db");
    let mut plugin = load_plugin(region, &[]);

    let req = resource_request(app, ns, "rds", &[("identifier", identifier)]);
    let result = call_provision(&mut plugin, &req);
    assert!(
        result.errors.is_empty(),
        "provision errors: {:?}",
        result.errors
    );

    let db = db_instance(&rds_client(region).await, identifier).await;
    assert_eq!(db.backup_retention_period(), Some(14));
    assert_eq!(db.copy_tags_to_snapshot(), Some(true));
    assert_eq!(db.deletion_protection(), Some(true));
}

/// Instances created with RDS's 1-day default (every instance the plugin
/// created before) are raised to the configured retention on the next
/// reconcile, without being lowered or recreated.
#[tokio::test]
async fn existing_rds_backup_retention_is_raised_on_reconcile() {
    let region = "us-gov-west-1";
    let (ns, app) = ("legacy-it", unique("legacy"));
    let identifier = unique("legacy-db");
    let rds = rds_client(region).await;
    rds.create_db_instance()
        .db_instance_identifier(identifier)
        .db_instance_class("db.t3.micro")
        .engine("postgres")
        .allocated_storage(20)
        .master_username("dbadmin")
        .master_user_password("not-a-real-password-1")
        .backup_retention_period(1)
        .send()
        .await
        .expect("seed a 1-day-retention instance");
    assert_eq!(
        db_instance(&rds, identifier)
            .await
            .backup_retention_period(),
        Some(1)
    );

    let mut plugin = load_plugin(region, &[("RDS_BACKUP_RETENTION_DAYS", "21")]);
    let req = resource_request(app, ns, "rds", &[("identifier", identifier)]);
    let result = call_provision(&mut plugin, &req);
    assert!(
        result.errors.is_empty(),
        "provision errors: {:?}",
        result.errors
    );

    assert_eq!(
        db_instance(&rds, identifier)
            .await
            .backup_retention_period(),
        Some(21),
        "retention must be raised to RDS_BACKUP_RETENTION_DAYS"
    );
}

/// Removing an RDS resource always leaves a timestamped final snapshot.
#[tokio::test]
async fn rds_deprovision_always_takes_a_final_snapshot() {
    let region = "us-gov-west-1";
    let (ns, app) = ("archive-it", unique("archive"));
    let identifier = unique("archive-db");
    let rds = rds_client(region).await;
    let mut plugin = load_plugin(region, &[]);

    let req = resource_request(app, ns, "rds", &[("identifier", identifier)]);
    let provisioned = call_provision(&mut plugin, &req);
    assert!(
        provisioned.errors.is_empty(),
        "provision errors: {:?}",
        provisioned.errors
    );

    let removed = call_deprovision(&mut plugin, &deprovision_request(&req, &provisioned));
    assert!(
        removed.errors.is_empty(),
        "deprovision errors: {:?}",
        removed.errors
    );

    let snapshots = rds
        .describe_db_snapshots()
        .db_instance_identifier(identifier)
        .snapshot_type("manual")
        .send()
        .await
        .expect("describe snapshots");
    let names: Vec<&str> = snapshots
        .db_snapshots()
        .iter()
        .filter_map(|s| s.db_snapshot_identifier())
        .collect();
    let prefix = format!("{identifier}-final-");
    assert!(
        names.iter().any(|n| n.starts_with(&prefix)),
        "expected a final snapshot named {prefix}YYYYMMDD-HHMMSS, got {names:?}"
    );
    assert!(
        removed.message.contains("final snapshot"),
        "message: {}",
        removed.message
    );
}

/// With RESOURCE_NAME_PREFIX set, every queue and secret the plugin creates is
/// named <prefix>…, so its IAM policy can be scoped to <prefix>* instead of all
/// queues and secrets in the account. Reconciling the stamped annotations must
/// reuse the same queue, never create a double-prefixed one.
#[tokio::test]
async fn resource_name_prefix_scopes_queue_and_secret_names() {
    let region = "us-gov-west-1";
    let prefix = format!("acme-dw-{}-", run_id());
    let (ns, app) = ("prefix-it", unique("prefixed"));
    let mut plugin = load_plugin(region, &[("RESOURCE_NAME_PREFIX", prefix.as_str())]);

    let sqs_req = resource_request(app, ns, "sqs", &[("queue_name", "orders")]);
    let sqs_res = call_provision(&mut plugin, &sqs_req);
    assert!(
        sqs_res.errors.is_empty(),
        "provision errors: {:?}",
        sqs_res.errors
    );
    let queue_name = format!("{prefix}orders");
    assert_eq!(sqs_res.state.get("QUEUE_NAME"), Some(&queue_name));
    assert_eq!(
        sqs_res
            .deployment_annotations
            .get("sqs.deckwatch.io/queue-name"),
        Some(&queue_name),
        "the stamped name is already prefixed"
    );

    let sm_req = resource_request(app, ns, "secretsmanager", &[]);
    let sm_res = call_provision(&mut plugin, &sm_req);
    assert!(
        sm_res.errors.is_empty(),
        "provision errors: {:?}",
        sm_res.errors
    );
    assert_eq!(
        sm_res.state.get("SM_SECRET_NAME"),
        Some(&format!("{prefix}{ns}/{app}"))
    );

    // Reconcile: apply() with the stamped annotations reuses the same queue.
    let applied = call_apply(
        &mut plugin,
        &PluginContext {
            namespace: ns.into(),
            deployment_name: "worker".into(),
            annotations: sqs_res.deployment_annotations.clone(),
            labels: HashMap::new(),
            plugin_outputs: HashMap::new(),
            provisioned_resources: HashMap::new(),
            ..Default::default()
        },
    );
    assert_eq!(
        applied.outputs.get("queue_url"),
        sqs_res.state.get("QUEUE_URL")
    );
    let queues = sqs_client(region)
        .await
        .list_queues()
        .queue_name_prefix(&prefix)
        .send()
        .await
        .expect("list queues");
    assert_eq!(
        queues.queue_urls().len(),
        1,
        "no double-prefixed duplicate queue: {:?}",
        queues.queue_urls()
    );
}

/// RESOURCE_TAGS (plus the managed ownership tags) reach every resource the
/// plugin manages, existing S3 bucket tags survive the merge, and
/// re-provisioning updates tags on resources that already exist.
#[tokio::test]
async fn resource_tags_are_applied_to_every_managed_resource() {
    let region = "us-gov-west-1";
    let (ns, app) = ("tagged-it", unique("tagged"));
    let (bucket, queue, db) = (
        unique("acme-tagged-assets"),
        unique("tagged-q"),
        unique("tagged-db"),
    );
    let role_name = format!("{ns}-{app}-rds");
    let expect = |team: &str| {
        tag_map([
            ("Team", team),
            ("CostCenter", "1234"),
            ("deckwatch.io/managed-by", "deckwatch-plugin-aws"),
            ("deckwatch.io/application", app),
            ("deckwatch.io/namespace", ns),
        ])
    };
    let contains = |actual: &HashMap<String, String>, wanted: &HashMap<String, String>| {
        wanted.iter().all(|(k, v)| actual.get(k) == Some(v))
    };

    // A bucket that already carries someone else's tag.
    let s3 = s3_client(region).await;
    s3.create_bucket()
        .bucket(bucket)
        .create_bucket_configuration(
            aws_sdk_s3::types::CreateBucketConfiguration::builder()
                .location_constraint(aws_sdk_s3::types::BucketLocationConstraint::from(region))
                .build(),
        )
        .send()
        .await
        .expect("seed bucket");
    s3.put_bucket_tagging()
        .bucket(bucket)
        .tagging(
            aws_sdk_s3::types::Tagging::builder()
                .tag_set(
                    aws_sdk_s3::types::Tag::builder()
                        .key("Owner")
                        .value("finance")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("seed bucket tag");

    for team in ["platform", "data"] {
        let tags_cfg = format!("Team={team},CostCenter=1234");
        let mut plugin = load_plugin(region, &[("RESOURCE_TAGS", tags_cfg.as_str())]);
        for req in [
            s3_request(app, ns, bucket, region),
            resource_request(app, ns, "sqs", &[("queue_name", queue)]),
            resource_request(app, ns, "secretsmanager", &[]),
            resource_request(app, ns, "rds", &[("identifier", db)]),
        ] {
            let result = call_provision(&mut plugin, &req);
            assert!(
                result.errors.is_empty(),
                "{} errors: {:?}",
                req.resource_id,
                result.errors
            );
        }
        let wanted = expect(team);

        let iam = iam_client(region).await;
        let role_tags = iam
            .list_role_tags()
            .role_name(&role_name)
            .send()
            .await
            .expect("role tags");
        let role_tags = tag_map(role_tags.tags().iter().map(|t| (t.key(), t.value())));
        assert!(
            contains(&role_tags, &wanted),
            "IAM role tags ({team}): {role_tags:?}"
        );

        let bucket_tags = s3
            .get_bucket_tagging()
            .bucket(bucket)
            .send()
            .await
            .expect("bucket tags");
        let bucket_tags = tag_map(bucket_tags.tag_set().iter().map(|t| (t.key(), t.value())));
        assert!(
            contains(&bucket_tags, &wanted),
            "S3 tags ({team}): {bucket_tags:?}"
        );
        assert_eq!(
            bucket_tags.get("Owner").map(String::as_str),
            Some("finance"),
            "foreign tag kept"
        );

        let sqs = sqs_client(region).await;
        let url = sqs
            .get_queue_url()
            .queue_name(queue)
            .send()
            .await
            .expect("queue")
            .queue_url()
            .unwrap()
            .to_string();
        let queue_tags = sqs
            .list_queue_tags()
            .queue_url(&url)
            .send()
            .await
            .expect("queue tags");
        let queue_tags: HashMap<String, String> = queue_tags.tags().cloned().unwrap_or_default();
        assert!(
            contains(&queue_tags, &wanted),
            "SQS tags ({team}): {queue_tags:?}"
        );

        let secret = secrets_client(region)
            .await
            .describe_secret()
            .secret_id(format!("{ns}/{app}"))
            .send()
            .await
            .expect("secret");
        let secret_tags = tag_map(
            secret
                .tags()
                .iter()
                .map(|t| (t.key().unwrap_or(""), t.value().unwrap_or(""))),
        );
        assert!(
            contains(&secret_tags, &wanted),
            "secret tags ({team}): {secret_tags:?}"
        );

        let instance = db_instance(&rds_client(region).await, db).await;
        let db_tags = tag_map(
            instance
                .tag_list()
                .iter()
                .map(|t| (t.key().unwrap_or(""), t.value().unwrap_or(""))),
        );
        assert!(
            contains(&db_tags, &wanted),
            "RDS tags ({team}): {db_tags:?}"
        );
    }
}

/// Annotation-scheduled AWS Backup snapshots create a tagged backup plan. The
/// plugin used to call CreateBackupPlan as POST with a "BackupPlanData" body,
/// which AWS Backup rejects, so no plan was ever created.
#[tokio::test]
async fn rds_snapshot_schedule_creates_a_tagged_backup_plan() {
    let region = "us-gov-west-1";
    let (ns, app) = ("backed-it", unique("backed"));
    let identifier = unique("backed-db");
    let mut plugin = load_plugin(region, &[("RESOURCE_TAGS", "Team=platform")]);
    let ctx = PluginContext {
        namespace: ns.into(),
        deployment_name: "api".into(),
        annotations: HashMap::from([
            ("aws.deckwatch.io/app-name".into(), app.into()),
            ("rds.deckwatch.io/enabled".into(), "true".into()),
            ("rds.deckwatch.io/identifier".into(), identifier.into()),
            (
                "rds.deckwatch.io/snapshot-schedule".into(),
                "cron(0 3 * * ? *)".into(),
            ),
            ("rds.deckwatch.io/snapshot-retention".into(), "30".into()),
            (
                "rds.deckwatch.io/backup-role-arn".into(),
                "arn:aws-us-gov:iam::123456789012:role/aws-backup".into(),
            ),
        ]),
        labels: HashMap::new(),
        plugin_outputs: HashMap::new(),
        provisioned_resources: HashMap::new(),
        ..Default::default()
    };
    // First reconcile creates the instance; the next one configures backups.
    call_apply(&mut plugin, &ctx);
    call_apply(&mut plugin, &ctx);

    let backup = backup_client(region).await;
    let plans = backup.list_backup_plans().send().await.expect("list plans");
    let plan_name = format!("{identifier}-backup");
    let plan = plans
        .backup_plans_list()
        .iter()
        .find(|p| p.backup_plan_name() == Some(plan_name.as_str()))
        .unwrap_or_else(|| panic!("backup plan {plan_name} must exist"));
    let tags = backup
        .list_tags()
        .resource_arn(plan.backup_plan_arn().unwrap())
        .send()
        .await
        .expect("plan tags");
    let tags: HashMap<String, String> = tags.tags().cloned().unwrap_or_default();
    assert_eq!(
        tags.get("Team").map(String::as_str),
        Some("platform"),
        "plan tags: {tags:?}"
    );
    assert_eq!(
        tags.get("deckwatch.io/application").map(String::as_str),
        Some(app)
    );
}

// ── Request recording (moto's /moto-api/recorder) ─────────────────────────────

/// Call moto's management API with a bare HTTP/1.1 request (the harness has
/// no HTTP client, and these endpoints need nothing more).
fn moto_api(method: &str, path: &str) -> String {
    use std::io::{Read, Write};
    let endpoint = moto_endpoint();
    let authority = endpoint
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut stream = std::net::TcpStream::connect(&authority).expect("connect to moto");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .expect("send to moto");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read from moto");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    assert!(
        head.lines().next().is_some_and(|l| l.contains(" 200")),
        "moto {method} {path}: {head}"
    );
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_string()
    }
}

/// Decode an HTTP/1.1 chunked body.
fn dechunk(mut body: &str) -> String {
    let mut out = String::new();
    while let Some((size_line, rest)) = body.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 || rest.len() < size {
            break;
        }
        out.push_str(&rest[..size]);
        body = rest[size..].trim_start_matches("\r\n");
    }
    out
}

/// Standard base64 (moto records request bodies base64-encoded).
fn base64_decode(s: &str) -> Vec<u8> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue, // padding and whitespace
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

/// Every request moto recorded that mentions `token`, as ("operation" or
/// "METHOD url", is_read). A request is a read when its Query `Action` or JSON
/// `X-Amz-Target` operation starts with Get, List or Describe, or when it's an
/// S3 GET; everything else counts as a write.
fn recorded_requests(recording: &str, token: &str) -> Vec<(String, bool)> {
    let is_read_op = |op: &str| {
        ["Get", "List", "Describe"]
            .iter()
            .any(|p| op.starts_with(p))
    };
    recording
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let entry: Value = serde_json::from_str(line).ok()?;
            let method = entry["method"].as_str().unwrap_or("");
            let url = entry["url"].as_str().unwrap_or("");
            let raw_body = entry["body"].as_str().unwrap_or("");
            let body = if entry["body_encoded"].as_bool() == Some(true) {
                String::from_utf8_lossy(&base64_decode(raw_body)).into_owned()
            } else {
                raw_body.to_string()
            };
            if !url.contains(token) && !body.contains(token) {
                return None;
            }
            let target = entry["headers"].as_object().and_then(|h| {
                h.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-target"))
                    .and_then(|(_, v)| v.as_str())
            });
            let action = body
                .split('&')
                .find_map(|kv| kv.strip_prefix("Action="))
                .map(str::to_string);
            let (op, is_read) = match (target, action) {
                (Some(t), _) => {
                    let op = t.rsplit('.').next().unwrap_or(t).to_string();
                    let read = is_read_op(&op);
                    (op, read)
                }
                (None, Some(a)) => {
                    let read = is_read_op(&a);
                    (a, read)
                }
                (None, None) => (format!("{method} {url}"), method == "GET"),
            };
            Some((op, is_read))
        })
        .collect()
}

/// Once everything exists and is configured, reconciling again must not write
/// to AWS. deckwatch can call apply() every few seconds, so a no-op reconcile
/// that still wrote would mean a constant stream of IAM, S3, SQS, Secrets
/// Manager and RDS writes. Changing an input must still write.
#[tokio::test]
async fn reconcile_without_changes_makes_no_aws_writes() {
    let region = "us-gov-west-1";
    let token = unique("noop");
    let ns = "noop-it";
    let bucket = format!("{token}-bucket");
    let queue = format!("{token}-queue");
    let secret = format!("{ns}/{token}");
    let identifier = format!("{token}-db");
    let ctx = PluginContext {
        namespace: ns.into(),
        deployment_name: "api".into(),
        annotations: HashMap::from([
            ("aws.deckwatch.io/app-name".into(), token.into()),
            ("s3.deckwatch.io/enabled".into(), "true".into()),
            ("s3.deckwatch.io/bucket-name".into(), bucket.clone()),
            ("s3.deckwatch.io/region".into(), region.into()),
            ("sqs.deckwatch.io/enabled".into(), "true".into()),
            ("sqs.deckwatch.io/queue-name".into(), queue.clone()),
            ("secretsmanager.deckwatch.io/enabled".into(), "true".into()),
            (
                "secretsmanager.deckwatch.io/secret-name".into(),
                secret.clone(),
            ),
            ("rds.deckwatch.io/enabled".into(), "true".into()),
            ("rds.deckwatch.io/identifier".into(), identifier.clone()),
        ]),
        ..Default::default()
    };

    let mut plugin = load_plugin(region, &[("RESOURCE_TAGS", "Team=platform")]);
    // The first reconcile creates everything. The second runs once the RDS
    // instance is available, and attaches its rds-db:connect policy.
    call_apply(&mut plugin, &ctx);
    call_apply(&mut plugin, &ctx);

    moto_api("POST", "/moto-api/recorder/reset-recording");
    moto_api("POST", "/moto-api/recorder/start-recording");
    let steady = call_apply(&mut plugin, &ctx);
    moto_api("POST", "/moto-api/recorder/stop-recording");
    let recording = moto_api("GET", "/moto-api/recorder/download-recording");
    moto_api("POST", "/moto-api/recorder/reset-recording");

    assert!(steady.errors.is_empty(), "errors: {:?}", steady.errors);
    let requests = recorded_requests(&recording, token);
    // The reconcile's own reads must be in the recording, or "no writes"
    // would pass vacuously.
    assert!(
        requests.iter().any(|(_, is_read)| *is_read),
        "the recorder captured none of this reconcile's requests"
    );
    let writes: Vec<&String> = requests
        .iter()
        .filter(|(_, is_read)| !is_read)
        .map(|(op, _)| op)
        .collect();
    assert!(
        writes.is_empty(),
        "a reconcile with nothing to change made AWS writes: {writes:#?}"
    );

    // A changed input is still written: every resource picks up the new value.
    let mut plugin = load_plugin(region, &[("RESOURCE_TAGS", "Team=rad")]);
    let changed = call_apply(&mut plugin, &ctx);
    assert!(changed.errors.is_empty(), "errors: {:?}", changed.errors);
    let want = |tags: &HashMap<String, String>, what: &str| {
        assert_eq!(
            tags.get("Team").map(String::as_str),
            Some("rad"),
            "{what} tags: {tags:?}"
        );
    };

    let role = format!("{ns}-{token}-role");
    let iam = iam_client(region).await;
    let role_tags = tag_map(
        iam.list_role_tags()
            .role_name(&role)
            .send()
            .await
            .expect("role tags")
            .tags()
            .iter()
            .map(|t| (t.key(), t.value())),
    );
    want(&role_tags, "role");

    let s3 = s3_client(region).await;
    let bucket_tags = tag_map(
        s3.get_bucket_tagging()
            .bucket(&bucket)
            .send()
            .await
            .expect("bucket tags")
            .tag_set()
            .iter()
            .map(|t| (t.key(), t.value())),
    );
    want(&bucket_tags, "bucket");

    let sqs = sqs_client(region).await;
    let queue_url = sqs
        .get_queue_url()
        .queue_name(&queue)
        .send()
        .await
        .expect("queue url")
        .queue_url()
        .expect("queue url")
        .to_string();
    let queue_tags: HashMap<String, String> = sqs
        .list_queue_tags()
        .queue_url(&queue_url)
        .send()
        .await
        .expect("queue tags")
        .tags()
        .cloned()
        .unwrap_or_default();
    want(&queue_tags, "queue");

    let secrets = secrets_client(region).await;
    let secret_tags = tag_map(
        secrets
            .describe_secret()
            .secret_id(&secret)
            .send()
            .await
            .expect("describe secret")
            .tags()
            .iter()
            .map(|t| (t.key().unwrap_or(""), t.value().unwrap_or(""))),
    );
    want(&secret_tags, "secret");

    let db = db_instance(&rds_client(region).await, &identifier).await;
    let db_tags = tag_map(
        db.tag_list()
            .iter()
            .map(|t| (t.key().unwrap_or(""), t.value().unwrap_or(""))),
    );
    want(&db_tags, "RDS instance");
}

/// RESOURCE_NAME_PREFIX names new S3 buckets too. The deprecated BUCKET_PREFIX
/// still wins while it's set, with a deprecation warning.
#[tokio::test]
async fn resource_name_prefix_names_new_buckets_and_bucket_prefix_still_wins() {
    let region = "us-gov-west-1";
    let prefix = format!("rp{}-", run_id());
    let s3 = s3_client(region).await;

    let mut plugin = load_plugin(region, &[("RESOURCE_NAME_PREFIX", prefix.as_str())]);
    let bucket = unique("fresh-assets");
    let provisioned = call_provision(
        &mut plugin,
        &s3_request(unique("fresh"), "prefix-it", bucket, region),
    );
    assert!(provisioned.errors.is_empty(), "{:?}", provisioned.errors);
    let full = format!("{prefix}{bucket}");
    assert_eq!(provisioned.state.get("S3_BUCKET"), Some(&full));
    s3.head_bucket()
        .bucket(&full)
        .send()
        .await
        .expect("the new bucket gets the prefix");
    assert!(
        s3.head_bucket().bucket(bucket).send().await.is_err(),
        "no unprefixed bucket"
    );

    let bucket_prefix = format!("bp{}-", run_id());
    let mut plugin = load_plugin(
        region,
        &[
            ("RESOURCE_NAME_PREFIX", prefix.as_str()),
            ("BUCKET_PREFIX", bucket_prefix.as_str()),
        ],
    );
    let bucket = unique("legacy-assets");
    let provisioned = call_provision(
        &mut plugin,
        &s3_request(unique("legacy"), "prefix-it", bucket, region),
    );
    assert!(provisioned.errors.is_empty(), "{:?}", provisioned.errors);
    assert_eq!(
        provisioned.state.get("S3_BUCKET"),
        Some(&format!("{bucket_prefix}{bucket}"))
    );
    assert!(
        provisioned
            .warnings
            .iter()
            .any(|w| w.contains("BUCKET_PREFIX is deprecated")),
        "warnings: {:?}",
        provisioned.warnings
    );
}

/// Setting RESOURCE_NAME_PREFIX after resources exist doesn't rename them. A
/// refresh (provisioning again) and a reconcile keep the existing bucket,
/// queue and secret, nothing is created under the prefix, and removing the
/// secret targets the one that exists.
#[tokio::test]
async fn setting_the_prefix_later_keeps_existing_resources() {
    let region = "us-gov-west-1";
    let (ns, app) = ("keep-it", unique("keep"));
    let bucket = format!("{app}-bucket");
    let queue = format!("{app}-queue");
    let secret = format!("{ns}/{app}");
    let prefix = format!("kp{}-", run_id());

    let requests = [
        s3_request(app, ns, &bucket, region),
        resource_request(app, ns, "sqs", &[("queue_name", queue.as_str())]),
        resource_request(
            app,
            ns,
            "secretsmanager",
            &[("secret_name", secret.as_str())],
        ),
    ];

    // Before the prefix is set: unprefixed names.
    let mut before = load_plugin(region, &[]);
    let originals: Vec<ResourceProvisionResult> = requests
        .iter()
        .map(|req| {
            let provisioned = call_provision(&mut before, req);
            assert!(provisioned.errors.is_empty(), "{:?}", provisioned.errors);
            provisioned
        })
        .collect();

    // The prefix is set, and every resource is refreshed.
    let mut after = load_plugin(region, &[("RESOURCE_NAME_PREFIX", prefix.as_str())]);
    for (req, original) in requests.iter().zip(&originals) {
        let refreshed = call_provision(&mut after, req);
        assert!(refreshed.errors.is_empty(), "{:?}", refreshed.errors);
        for key in [
            "S3_BUCKET",
            "QUEUE_URL",
            "QUEUE_NAME",
            "SM_SECRET_ARN",
            "SM_SECRET_NAME",
        ] {
            assert_eq!(
                refreshed.state.get(key),
                original.state.get(key),
                "{} {key}",
                req.resource_id
            );
        }
        assert!(
            refreshed
                .warnings
                .iter()
                .any(|w| w.contains("Kept the existing")),
            "{}: {:?}",
            req.resource_id,
            refreshed.warnings
        );
    }

    // A reconcile from the stamped annotations keeps the names too.
    let mut annotations: HashMap<String, String> = HashMap::new();
    for original in &originals {
        annotations.extend(original.deployment_annotations.clone());
    }
    let ctx = PluginContext {
        namespace: ns.into(),
        deployment_name: "api".into(),
        annotations,
        ..Default::default()
    };
    let applied = call_apply(&mut after, &ctx);
    assert!(applied.errors.is_empty(), "{:?}", applied.errors);
    let env = |name: &str| {
        applied
            .env_vars
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.value.clone())
    };
    assert_eq!(env("S3_BUCKET").as_deref(), Some(bucket.as_str()));
    assert_eq!(env("QUEUE_NAME").as_deref(), Some(queue.as_str()));

    // Nothing was created under the prefix.
    assert!(
        s3_client(region)
            .await
            .head_bucket()
            .bucket(format!("{prefix}{bucket}"))
            .send()
            .await
            .is_err(),
        "no prefixed bucket"
    );
    assert!(
        sqs_client(region)
            .await
            .get_queue_url()
            .queue_name(format!("{prefix}{queue}"))
            .send()
            .await
            .is_err(),
        "no prefixed queue"
    );
    assert!(
        secrets_client(region)
            .await
            .describe_secret()
            .secret_id(format!("{prefix}{secret}"))
            .send()
            .await
            .is_err(),
        "no prefixed secret"
    );

    // Removing the secret removes the one that exists, not a prefixed name.
    let removed = call_deprovision(
        &mut after,
        &deprovision_request(&requests[2], &originals[2]),
    );
    assert!(removed.errors.is_empty(), "{:?}", removed.errors);
    let described = secrets_client(region)
        .await
        .describe_secret()
        .secret_id(&secret)
        .send()
        .await
        .expect("still restorable during the recovery window");
    assert!(
        described.deleted_date().is_some(),
        "the existing secret is scheduled for deletion"
    );
}

/// A malformed AWS_ENDPOINT_URL must fail provisioning outright rather than
/// fall back to real AWS endpoints.
#[test]
fn malformed_endpoint_override_fails_closed() {
    let mut plugin = load_plugin("us-gov-west-1", &[("AWS_ENDPOINT_URL", "localhost:5000")]);
    let result = call_provision(
        &mut plugin,
        &s3_request("never", "never-it", "never-created-bucket", "us-gov-west-1"),
    );
    let joined = result.errors.join("; ");
    assert!(
        joined.contains("AWS_ENDPOINT_URL"),
        "expected an AWS_ENDPOINT_URL error, got: {joined:?}"
    );
}
