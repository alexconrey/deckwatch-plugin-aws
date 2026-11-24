# Development

- [Architecture](#architecture)
- [Building](#building)
- [Testing](#testing)
- [CI](#ci)
- [Pull requests](#pull-requests)
- [Releasing](#releasing)
- [Dependencies](#dependencies)

## Architecture

The plugin is a Rust `cdylib`, compiled to `wasm32-unknown-unknown` and run by
deckwatch through [extism](https://extism.org). It calls AWS APIs over HTTP with its
own SigV4 signing, because the AWS SDK doesn't run in this WASM sandbox.

```
src/
├── lib.rs            exports (metadata, apply, provision, deprovision), config parsing,
│                     orchestration, pure helpers (policies, ARNs, naming), unit tests
├── aws_sign.rs       SigV4 signing (hmac + sha2) + known-answer tests
├── iam.rs            IAM Query API: ensure_role (trust policy, tags), attach_*_policy,
│                     list/delete for deprovisioning
├── rds.rs            RDS Query API: ensure_instance (tags, backup retention),
│                     delete_instance (always with a final snapshot)
├── s3.rs             S3 REST: ensure_bucket (+ versioning, public access block, lifecycle,
│                     tag merge; Content-MD5 on configuration PUTs)
├── sqs.rs            SQS Query API: ensure_queue, queue_message_count, delete_queue
├── secretsmanager.rs Secrets Manager JSON API: ensure_secret, schedule_delete_secret
├── backup.rs         AWS Backup REST-JSON: configure_backup (plan + selection)
└── sts.rs            STS AssumeRoleWithWebIdentity (IRSA credentials)
integration/          end-to-end tests: plugin.wasm in extism against moto
```

| Export | Called | Purpose |
|---|---|---|
| `metadata()` | once, when the plugin loads | name, version, capabilities, config schema, provisionable resources |
| `provision()` | when a resource is added or refreshed | create the resource; return state (env vars), deployment annotations, Kubernetes resources |
| `apply()` | on every deployment create and update | read annotations, reconcile resources and IAM, return env vars and a `wants_service_account` request |
| `deprovision()` | when a resource is removed | clean up (see [Operations](operations.md#removing-a-resource)) |

### Host-testable by design

`extism-pdk` only links on `wasm32`, so the AWS API modules are `#[cfg(target_arch =
"wasm32")]`, and **tests inside them never run** on the host. Anything worth testing
therefore lives as a **pure function in `lib.rs`**, compiled for `wasm32` and for
tests, and the API modules call it with `crate::…`. Examples include annotation
parsing (`AwsConfig::from_context`), policy documents (`s3_access_policy_document`),
ARNs (`aws_partition`, `sqs_queue_arn`, `rds_instance_arn`), endpoint resolution
(`resolve_endpoint`), naming and tags (`prefixed_name`, `parse_resource_tags`),
backup retention (`retention_action`), deprovisioning decisions
(`final_snapshot_identifier`, `role_is_disposable`), secret write scoping
(`writable_secret_arns`) and the bootstrap Job manifests. Put new logic in the
same place.

## Building

Requirements: Rust stable (1.96+ for the integration harness) and the `wasm32` target.

```bash
rustup target add wasm32-unknown-unknown
make build          # → dist/plugin.wasm
```

The Makefile builds with `--locked`, as CI does, so it fails if `Cargo.lock` is
out of sync with `Cargo.toml`. See [Dependencies](#dependencies) for how to
update the lockfile.

`.cargo/config.toml` makes `wasm32-unknown-unknown` the default build target. That's
why host test commands pass `--target <host triple>` explicitly.

## Testing

| Layer | Command | Covers |
|---|---|---|
| Unit | `make test` | Annotation parsing, naming and the name prefix, tag parsing and encoding, policy documents (including secret write scoping), ARNs and partitions, endpoint resolution, backup retention, deprovisioning decisions, bootstrap SQL and manifests |
| Known-answer | part of `make test` (`aws_sign::tests`) | SHA-256 and HMAC (RFC 4231) vectors, the AWS signing-key example, and a golden `Authorization` header. **The only tests that catch a signing regression**, because moto doesn't verify signatures. |
| Integration | `make integration` | The built `plugin.wasm` in a stock extism host against moto, checked through the AWS SDK. See [integration/README.md](../integration/README.md). |

```bash
docker run --rm -d -p 5000:5000 --name moto motoserver/moto:5.2.6
make integration                         # or MOTO_ENDPOINT=http://localhost:5055
```

The extism host in the integration tests may only reach the moto host, so a test
fails if the plugin tries to call real AWS.

**What moto can't catch:**
- **Signatures.** moto doesn't verify them. Before changing signing or the
  crypto dependencies, check that the golden `Authorization` header in
  `aws_sign.rs` still matches byte for byte. Only re-capture it if the signed
  request format itself changes on purpose.
- **IAM permissions.** moto allows every call, so nothing tests the plugin's own
  policy. When a change adds an AWS call, or adds tags to a create call (AWS
  checks tag-on-create against the tagging action), update
  [Plugin IAM permissions](configuration.md#plugin-iam-permissions) and the
  CHANGELOG's *Upgrade notes* by hand.
- **Wire-format details** moto happens to accept. When adding an API call,
  compare the plugin's request with `aws <service> <operation> --debug` against
  moto: the method, path, body member names and `Content-Type` should match what
  the AWS SDKs send. That comparison found the AWS Backup client's wrong method,
  body and content type.

**Mutation-check new tests:** break the fix on purpose and confirm the test fails.

Lint both targets before pushing. CI only lints the host build, but the AWS API
modules compile only for `wasm32`:

```bash
cargo clippy --target "$(rustc -vV | sed -n 's/^host: //p')" --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown -- -D warnings
```

## CI

`.github/workflows/ci.yml` runs on every push and on PRs to `main`:

| Job | Runs |
|---|---|
| Lockfiles match Cargo.toml | `cargo metadata --locked` for the plugin and the harness. Fails if either lockfile is missing or out of sync with its `Cargo.toml` |
| Unit tests | `cargo test --locked --target <host>` |
| Build WASM | `cargo build --locked --release --target wasm32-unknown-unknown` |
| Clippy | `cargo clippy --locked --target <host> -- -D warnings` |
| Rustfmt | `cargo fmt --check` |
| Integration | builds `plugin.wasm`, starts `motoserver/moto:5.2.6` as a service, lints the harness, runs `cargo test --locked` in `integration/` |

`release.yml` also builds with `--locked`, so the released `plugin.wasm` uses
the same dependency versions CI tested.

## Pull requests

- **Branch every PR from `main`, and don't stack PRs.** GitHub merges a PR into
  its base branch, so a PR based on another feature branch lands on that branch,
  not on `main`, and has to be landed again. If one change needs another, wait
  for the first to merge, then rebase onto `main`.
- Update the docs page that describes the behaviour and the CHANGELOG's
  *Unreleased* section in the same PR. The table in
  [CLAUDE.md](../CLAUDE.md#documentation) maps changes to pages.
- Merge only after CI passes.

## Releasing

1. **Bump `version` in `Cargo.toml`** in its own PR (`chore: set version to X.Y.Z`).
   The plugin reports this version to deckwatch, so skipping the bump makes a new
   build look like the previous release.
2. Update [CHANGELOG.md](../CHANGELOG.md): move the *Unreleased* entries under the
   new version. Add *Upgrade notes* for anything operators must do before the new
   binary runs, especially new plugin IAM permissions.
3. After merging, tag `main` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `.github/workflows/release.yml` builds `plugin.wasm` and attaches it to the
   GitHub Release, with generated notes.
5. Point deckwatch's plugin source at the new tag (see
   [Configuration](configuration.md#installing-the-plugin)), and check that the
   loaded `sha256` matches the release asset (see
   [Verifying the loaded binary](operations.md#verifying-the-loaded-binary)).

## Dependencies

[Dependabot](../.github/dependabot.yml) proposes weekly updates for the plugin
crate, the integration harness and the GitHub Actions:

- **`hmac`, `sha2`, `md-5` and `digest` are grouped and always move together.**
  They share the `digest` trait crate, and upgrading only one fails to compile.
- **Minor and patch updates are grouped** per ecosystem, and the `aws-*` harness
  crates move in lockstep.
- **Lockfiles are committed**, for the plugin (`Cargo.lock`) and the harness
  (`integration/Cargo.lock`). CI, `release.yml` and the Makefile build with
  `--locked`, so a release uses exactly the versions CI tested. A lockfile that
  doesn't match its `Cargo.toml` fails the *Lockfiles match Cargo.toml* CI job.
  After editing a `Cargo.toml`, run `cargo update --workspace` in that directory
  and commit the updated lockfile with it. A bare `cargo update` bumps every
  dependency.
- **`deckwatch-plugin-sdk` is pinned to a commit** (`rev`) in both `Cargo.toml`
  and `integration/Cargo.toml`, and the two must match. Bump the pin in its own
  PR so CI tests the new SDK before a release uses it.
- deckwatch keeps its own hand-written copy of the SDK's types, so a new SDK type
  (such as the `key_value` config field type) does nothing until deckwatch
  supports it too.

Dependabot can't see these container images; update them by hand:

| Image | Where |
|---|---|
| `motoserver/moto` | `.github/workflows/ci.yml`, `Makefile`, `integration/README.md`, `CLAUDE.md`, this page |
| `amazon/aws-cli` | `DEFAULT_BOOTSTRAP_AWSCLI_IMAGE` in `src/lib.rs` |
| `postgres` | `DEFAULT_BOOTSTRAP_PSQL_IMAGE` in `src/lib.rs` |
