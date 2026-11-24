# Claude assistant instructions — deckwatch-plugin-aws

A deckwatch plugin (Rust → `wasm32-unknown-unknown`, run by extism) that provisions
AWS resources (IAM, RDS, S3, SQS, Secrets Manager, ECR, AWS Backup) and wires them to
an application through **one IAM role and one IRSA ServiceAccount per application**.
It must work in commercial AWS **and GovCloud**.

User and operator documentation lives in [`docs/`](docs/). Keep it in sync, as
described in [Documentation](#documentation) below.

## Architecture in one screen

| Export | When deckwatch calls it | Notes |
|---|---|---|
| `metadata()` | once, when the plugin loads | Config schema, resources, capabilities, version (`CARGO_PKG_VERSION`) |
| `provision()` | resource added or refreshed | Returns `state` (env vars for every deployment), `deployment_annotations`, `kubernetes_resources` |
| `apply()` | every deployment create and update | Reads `*.deckwatch.io/*` annotations; reconciles resources and IAM; returns env vars and `wants_service_account` |
| `deprovision()` | resource removed | RDS deleted (final snapshot by default); S3 kept; SQS deleted; secret scheduled for deletion |

`src/lib.rs` holds the exports, config parsing (`AwsConfig::from_context`) and pure
helpers. The API clients are `iam.rs`, `rds.rs`, `s3.rs`, `sqs.rs`,
`secretsmanager.rs`, `backup.rs` and `sts.rs`. Signing is in `aws_sign.rs`.
`integration/` holds the moto end-to-end harness.

## Rules that prevent the bugs we've actually had

1. **Never hardcode `arn:aws:`.** Build every ARN with `aws_partition(region)`. A
   policy with the wrong partition is accepted by IAM but matches nothing. The S3,
   SQS and Backup ARNs all had this bug in GovCloud.
2. **Put testable logic in `lib.rs` as pure functions.** The API modules are
   `#[cfg(target_arch = "wasm32")]`, so **tests inside them never run** on the host
   (the old SQS tests never ran). Gate helpers with
   `#[cfg(any(target_arch = "wasm32", test))]` and call them as `crate::…`.
3. **`provision()` must stamp the annotations `apply()` needs**
   (`rds_apply_annotations`, `s3_apply_annotations`, `sqs_apply_annotations`,
   `secretsmanager_apply_annotations`), or reconciliation never picks
   the resource up. Stamp names *without* `BUCKET_PREFIX`; `apply()` adds it.
4. **Grant IAM when you create a resource.** Creating a bucket or queue without
   attaching the matching inline policy to the app role leaves the workload with
   `AccessDenied`. Use `bind_workload_identity()` in `provision()`: it ensures the
   role `rds_role_name(ns, app)` (`<ns>-<app>-rds`, a historical name; don't rename
   it), attaches the policy and emits the ServiceAccount. Policy names are the
   `POLICY_*` constants, one per resource type.
5. **"Not found" is often an HTTP 4xx.** Map it to `Ok(None)` before propagating
   errors (IAM `NoSuchEntity`, SQS `NonExistentQueue`). Include the AWS error `Code`
   in error strings so these checks have something to match.
6. **Only request the ServiceAccount after the role exists.** `apply_inner` is the
   no-AWS fallback and must not set `wants_service_account`.
7. **No clock, no filesystem.** Time comes from the `CURRENT_TIMESTAMP` config value,
   which deckwatch injects. Credentials come from config (IRSA token via
   `inherit_env_file_keys`).
8. **Every outgoing URL goes through `service_endpoint()`**, so `AWS_ENDPOINT_URL` can
   redirect it in tests. A malformed override must fail, never fall back to AWS.
9. **Deprovisioning never destroys data without a recovery path.** RDS always takes a
   final snapshot (there's no skip option) and keeps its automated backups, S3
   buckets are kept, SQS queues with messages are kept, and secrets keep their
   recovery window. RDS automated-backup retention defaults to 14 days and is only
   ever raised on reconcile, never lowered or disabled. Revoke IAM only for
   resources that were actually removed, and delete the role only when
   `role_is_disposable()` says nothing is left on it.
10. **Parse JSON with `serde_json`** (`json_str_field`), never with `"key":"`
    substring matching. AWS doesn't promise compact JSON, and some fields are
    numbers.

## Testing

| Command | What |
|---|---|
| `make test` | Unit tests on the host (`.cargo/config.toml` defaults to wasm32, so the Makefile passes the host triple) |
| `make build` | `dist/plugin.wasm` |
| `make integration` | Needs moto: `docker run --rm -d -p 5000:5000 motoserver/moto:5.2.6` |

- **Known-answer tests in `aws_sign.rs` are the only signing check**, because moto
  doesn't verify signatures. The golden `Authorization` header must still match after
  any crypto or dependency change; don't re-capture it to make a test pass.
- **Integration tests** load the real `plugin.wasm` in extism, which may only reach
  moto, and verify state through the AWS SDK. Name resources with `unique(…)`.
- **Mutation-check new tests**: break the fix on purpose and confirm the test fails.
- Run clippy for **both** targets: `cargo clippy --target <host> --all-targets -- -D warnings`
  and `cargo clippy --target wasm32-unknown-unknown -- -D warnings`.

## Dependencies

- `hmac`, `sha2` and `digest` must be upgraded **together**; Dependabot groups them.
- Container images Dependabot can't see: moto (CI, Makefile, docs), and
  `DEFAULT_BOOTSTRAP_AWSCLI_IMAGE` / `DEFAULT_BOOTSTRAP_PSQL_IMAGE` in `src/lib.rs`.
- Lockfiles are git-ignored on purpose.

## Releasing

Bump `Cargo.toml` `version` in its own PR (`chore: set version to X.Y.Z`); the
plugin reports it to deckwatch. Move the CHANGELOG *Unreleased* entries under the new
version, then tag `vX.Y.Z` on `main`. `release.yml` attaches `plugin.wasm` to the
release. To test an unreleased build in deckwatch, upload the **raw bytes**:
`curl -X POST -H 'Content-Type: application/wasm' --data-binary @dist/plugin.wasm https://<deckwatch>/api/plugins/AWS/upload`.
Multipart form data is rejected.

## Documentation

When you change behaviour, update the page that describes it in the same PR:

| Change | Update |
|---|---|
| Config key (`metadata().config_schema`) | `docs/configuration.md` |
| AWS API call | `docs/configuration.md#plugin-iam-permissions`, and `allowed_hosts` if it's a new host |
| Resource field, annotation, env var, output, naming | `docs/resources.md` |
| Role, trust policy, inline policy, partition, bootstrap Job | `docs/identity.md` |
| Refresh, deprovision or upgrade behaviour; limitations | `docs/operations.md` |
| Build, test, CI, release process | `docs/development.md` |
| Anything user-visible | `CHANGELOG.md` → *Unreleased* |

## Git workflow

- **Never** push or commit directly to `main`.
- **Never** merge a PR without CI passing.
- All changes go through a feature branch and PR.
- No Co-Authored-By lines in commits for this repo.
