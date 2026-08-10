# Claude assistant instructions — deckwatch-plugin-aws

## Project overview

`deckwatch-plugin-aws` is a **unified** deckwatch plugin that provisions three
categories of AWS infrastructure for a Kubernetes workload in a single WASM
binary:

| Resource category | Annotation namespace |
|---|---|
| IAM role + IRSA ServiceAccount | `aws.deckwatch.io/` |
| RDS DB instance | `rds.deckwatch.io/` |
| S3 bucket | `s3.deckwatch.io/` |
| AWS Backup snapshot schedule | `rds.deckwatch.io/snapshot-*` |

The key design decision is **one role per workload**. Rather than having three
separate plugins each managing isolated IAM state, this plugin creates a single
role and attaches inline policies to it for each enabled resource. This keeps
IAM state minimal and makes it easy for operators to audit what a workload can
access.

### Why one plugin instead of three?

A separate IAM plugin, RDS plugin, and S3 plugin would each need to create or
reference IAM roles. Coordinating role ownership across plugins requires complex
`plugin_outputs` handshakes and ordering guarantees. Merging them into one
plugin avoids that coupling entirely: one binary owns the role lifecycle and
attaches policies to it atomically.

The SDK's `PluginMetadata.provides` capability IDs allow downstream plugins to
declare a dependency on `"aws:iam-role"` or `"aws:rds-connection"` without
caring whether those came from this plugin or a future specialist one.

## Architecture

```
src/
├── lib.rs        orchestration; metadata() + apply() WASM exports; 13 unit tests
├── aws_sign.rs   AWS Sig V4 signing + utc_now_iso8601 (pure Rust, no extism)
├── iam.rs        IAM Query API — ensure_role, attach_*_policy  (WASM only)
├── rds.rs        RDS Query API — ensure_instance               (WASM only)
├── s3.rs         S3 REST API   — ensure_bucket                 (WASM only)
└── backup.rs     AWS Backup REST-JSON — configure_backup       (WASM only)
```

### extism-pdk WASM-only pattern

`extism-pdk` is declared under `[target.'cfg(target_arch = "wasm32")'.dependencies]`
so it never links on host targets. All four API modules (`iam`, `rds`, `s3`,
`backup`) are declared in `lib.rs` as `#[cfg(target_arch = "wasm32")] mod …;`,
so they are invisible to the host compiler. The `#[plugin_fn]` macro and all
`extism_pdk::*` imports are similarly gated.

The pure orchestration (`apply_inner`) and SA YAML generation live in `lib.rs`
with no cfg guard, making them available to host-side unit tests.

### `metadata()` + `apply()` dual export

`metadata()` is called once at plugin load time by deckwatch to build the
dependency graph. `apply()` is called for every deployment create/update event.

### AWS Backup for snapshots (not CronJob)

Snapshot scheduling is implemented via **AWS Backup**, not a Kubernetes
`CronJob`. The `backup.rs` module calls `CreateBackupPlan` and
`CreateBackupSelection` against the `backup.<region>.amazonaws.com` REST-JSON
endpoint. This produces no `kubernetes_resources`; all schedule state lives in
AWS.

## Annotation reference

### Global (`aws.deckwatch.io/`)

| Key | Value | Notes |
|---|---|---|
| `aws.deckwatch.io/enabled` | `"true"` | Master opt-in; also implied by any rds/s3 annotation |
| `aws.deckwatch.io/role-name` | `"myapp-role"` | Optional; defaults to `<namespace>-<deployment>-role` |

### RDS (`rds.deckwatch.io/`)

| Key | Default | Notes |
|---|---|---|
| `rds.deckwatch.io/enabled` | — | Must be `"true"` to provision |
| `rds.deckwatch.io/engine` | `"postgres"` | `"postgres"` or `"mysql"` |
| `rds.deckwatch.io/instance-class` | `"db.t3.micro"` | |
| `rds.deckwatch.io/allocated-storage` | `"20"` | GiB |
| `rds.deckwatch.io/identifier` | `<ns>-<deploy>-db` | Max 63 chars |
| `rds.deckwatch.io/db-name` | `"app"` | Initial database name |
| `rds.deckwatch.io/multi-az` | `"false"` | |
| `rds.deckwatch.io/subnet-group` | — | Optional |
| `rds.deckwatch.io/security-groups` | — | Comma-separated SG IDs |
| `rds.deckwatch.io/iam-auth` | `"false"` | IAM database auth; sets `DB_IAM_AUTH=true` |
| `rds.deckwatch.io/snapshot-schedule` | — | AWS EventBridge cron, e.g. `"cron(0 3 * * ? *)"` |
| `rds.deckwatch.io/snapshot-retention` | `"7"` | Backup retention in days |
| `rds.deckwatch.io/backup-role-arn` | — | IAM role for `backup.amazonaws.com` |

### S3 (`s3.deckwatch.io/`)

| Key | Default | Notes |
|---|---|---|
| `s3.deckwatch.io/enabled` | — | Must be `"true"` to provision |
| `s3.deckwatch.io/bucket-name` | — | Suffix after `BUCKET_PREFIX` extism config |
| `s3.deckwatch.io/region` | `"us-east-1"` | |
| `s3.deckwatch.io/versioning` | `"false"` | |
| `s3.deckwatch.io/public-access-block` | `"true"` | |
| `s3.deckwatch.io/lifecycle-days` | — | Expire objects after N days |

## The `plugin_outputs` system

This plugin sets the following keys in `result.outputs` (accessible to
downstream plugins via `ctx.plugin_outputs["aws"]`):

| Key | Value |
|---|---|
| `role_arn` | The IAM role ARN created for this workload |
| `service_account_name` | The SA name bound to the pod |
| `rds_endpoint` | RDS instance hostname (empty while provisioning) |
| `s3_bucket` | Full bucket name (prefix applied) |

Example — a downstream plugin reading the role ARN:

```rust
if let Some(aws_out) = ctx.plugin_outputs.get("aws") {
    if let Some(role_arn) = aws_out.get("role_arn") {
        // attach additional policies to this role
    }
}
```

## Git workflow

- **Never** push or commit directly to `main`.
- **Never** merge a PR without CI passing.
- All changes go through a feature branch and PR.
- No Co-Authored-By lines in commits for this repo.

## Building

```bash
make build   # cargo build --release --target wasm32-unknown-unknown
make test    # cargo test --target <host>
make clean   # remove build artefacts
```
