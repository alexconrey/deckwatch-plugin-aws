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
| `deprovision()` | resource removed | RDS: final snapshot (always), automated backups kept; S3 kept; SQS deleted only if empty; secret scheduled for deletion (30-day window). Then the resource's inline policy is removed and the role deleted once nothing is left on it |

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
   in error strings so these checks have something to match. **Under path-scoped
   IAM grants, a call on a missing role returns `AccessDenied`, not
   `NoSuchEntity`** (IAM authorizes it against `role/<name>` without the path), so
   look before you delete: deprovisioning lists a role's policies and only deletes
   what's there.
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
10. **Parse and build JSON with `serde_json`** (`json_str_field`, `json!`), never
    with `"key":"` substring matching or `format!`. AWS doesn't promise compact
    JSON, some fields are numbers, and values must be escaped.
11. **Every create path passes `tags` and every SQS/secret name goes through
    `prefixed_name`.** Tags come from `configured_resource_tags(app, ns)`; the
    name prefix from `RESOURCE_NAME_PREFIX`. Both keep the operator's IAM scoping
    and cost allocation intact; a resource created without them escapes both.
12. **Match the AWS SDKs' wire format exactly**: method, path, body members and
    Content-Type. Check `aws <service> <op> --debug` against moto when adding an
    API; that's how the Backup client's POST/`BackupPlanData`/JSON-RPC
    content-type bug was found.
13. **Grant write access only to secrets the plugin created.** `PutSecretValue`
    goes on `secretsmanager.deckwatch.io/owned-secret-arns` (stamped by
    provisioning), filtered by `writable_secret_arns()` to names under
    `RESOURCE_NAME_PREFIX`. Secrets referenced with `secret-arns` stay read-only.
14. **moto doesn't check IAM, so nothing tests the plugin's own policy.** When you
    add an AWS call, or add tags to a create call (AWS checks tag-on-create
    against the tagging action: `CreateRole` with tags needs `iam:TagRole`),
    update `docs/configuration.md#plugin-iam-permissions` and the CHANGELOG
    *Upgrade notes* in the same PR. Tagging was merged with a documented policy
    that lacked `iam:TagRole`, which blocks role creation, and no test caught it.

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
  and `cargo clippy --target wasm32-unknown-unknown -- -D warnings`. CI only lints
  the host build.
- moto 5.2.6 returns HTTP 500 for `CreateBackupSelection` (the AWS CLI gets the
  same), so the Backup integration test checks the plan and its tags only.

## Dependencies

- `hmac`, `sha2`, `md-5` and `digest` must be upgraded **together**; Dependabot's
  `rustcrypto` group keeps them in one PR.
- Container images Dependabot can't see: moto (CI, Makefile, docs), and
  `DEFAULT_BOOTSTRAP_AWSCLI_IMAGE` / `DEFAULT_BOOTSTRAP_PSQL_IMAGE` in `src/lib.rs`.
- Lockfiles are git-ignored on purpose.
- **`deckwatch-plugin-sdk` is pinned to a commit (`rev`)** in both `Cargo.toml`
  and `integration/Cargo.toml`; keep the two identical. Never go back to
  `branch = "main"`. Without a lockfile, every build, including the release
  build of a tag, compiles whatever the SDK's `main` is at that moment. That's
  how the first v0.8.0 release build broke minutes after CI passed. Bump the rev
  (or switch to a tag once the SDK publishes one) in its own PR, with CI.
  v0.10.0's `delete_kubernetes_resources` needs a bump past the current pin.
- deckwatch mirrors the SDK types by hand, so a new SDK type (e.g.
  `ConfigFieldType::KeyValue`) only works once deckwatch supports it. That's why
  `RESOURCE_TAGS` is still a `String` field that also accepts `key_value`'s JSON.

## Releasing

1. Bump `Cargo.toml` `version` in its own PR (`chore: set version to X.Y.Z`); the
   plugin reports it to deckwatch. Move the CHANGELOG *Unreleased* entries under
   the new version, with *Upgrade notes* for anything operators must do first
   (new plugin IAM actions above all).
2. After CI passes and the user merges, tag `vX.Y.Z` on `main`. Never tag before
   the merge. `release.yml` attaches `plugin.wasm` to the release.
3. Rolling it out (pointing deckwatch at the tag, or uploading) is a live change;
   see [Live environments](#live-environments). Afterwards, compare the loaded
   `sha256` from `GET /api/plugins` with the release asset.

To test an unreleased build in deckwatch, upload the **raw bytes**:
`curl -X POST -H 'Content-Type: application/wasm' --data-binary @dist/plugin.wasm https://<deckwatch>/api/plugins/AWS/upload`.
Multipart form data is rejected.

## Live environments

Work on this plugin often means investigating a deployed deckwatch (its MCP
server) and the AWS account behind it.

- **Ask before every live change**, and name the exact change: AWS writes
  (`put-role-policy`, `create-secret`, …), plugin uploads, plugin config changes,
  and refreshing or deprovisioning resources. Approval for one change doesn't
  cover the next. Read-only calls (`describe-*`, `get-*`, `list-*`, deckwatch
  `get_*`/`list_*`) are fine.
- **Hand-made grants get their own policy name** (`manual-<purpose>`), never a
  `deckwatch-*` one, which the next reconcile would overwrite. Remove them once
  the plugin covers the access. Until then they keep the role from being deleted.
  See `docs/operations.md#granting-access-by-hand`.
- **This repo is public.** Keep account IDs, hostnames, and cluster or customer
  names out of commits, docs and PR text. Use placeholders such as `<account>`
  and `<deckwatch-host>`.

## Documentation

When you change behaviour, update the page that describes it in the same PR:

| Change | Update |
|---|---|
| Config key (`metadata().config_schema`) | `docs/configuration.md` |
| AWS API call, or tags on a create call | `docs/configuration.md#plugin-iam-permissions` (and `allowed_hosts` if it's a new host), plus CHANGELOG *Upgrade notes* |
| Resource field, annotation, env var, output, naming | `docs/resources.md` |
| Role, trust policy, inline policy, partition, bootstrap Job | `docs/identity.md` |
| Refresh, deprovision or upgrade behaviour; limitations | `docs/operations.md` |
| Build, test, CI, release process | `docs/development.md` |
| Integration test coverage, moto caveats | `integration/README.md` |
| Anything user-visible | `CHANGELOG.md` → *Unreleased* |

## Git workflow

- **Never** push or commit directly to `main`.
- **Never** merge a PR without CI passing.
- All changes go through a feature branch and PR.
- **Branch every PR from `main`; don't stack PRs.** GitHub merges a PR into its
  base branch, so a stacked PR lands on the other feature branch, not `main`
  (#31 and #32 had to be re-landed through #35). Wait for the first PR to merge,
  then rebase onto `main`.
- No Co-Authored-By lines or other AI attribution in commits or PR descriptions
  for this repo.
