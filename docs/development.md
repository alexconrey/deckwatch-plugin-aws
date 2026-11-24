# Development

- [Architecture](#architecture)
- [Building](#building)
- [Testing](#testing)
- [CI](#ci)
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
├── iam.rs            IAM Query API: ensure_role, trust policy, attach_*_policy
├── rds.rs            RDS Query API: ensure_instance, delete_instance
├── s3.rs             S3 REST: ensure_bucket (+ versioning, public access block, lifecycle)
├── sqs.rs            SQS Query API: ensure_queue, delete_queue
├── secretsmanager.rs Secrets Manager JSON API: ensure_secret, schedule_delete_secret
├── backup.rs         AWS Backup REST-JSON: configure_backup
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
(`resolve_endpoint`) and the bootstrap Job manifests. Put new logic in the same
place.

## Building

Requirements: Rust stable (1.96+ for the integration harness) and the `wasm32` target.

```bash
rustup target add wasm32-unknown-unknown
make build          # → dist/plugin.wasm
```

`.cargo/config.toml` makes `wasm32-unknown-unknown` the default build target. That's
why host test commands pass `--target <host triple>` explicitly.

## Testing

| Layer | Command | Covers |
|---|---|---|
| Unit | `make test` | Annotation parsing, naming, policy documents, ARNs and partitions, endpoint resolution, bootstrap SQL and manifests |
| Known-answer | part of `make test` (`aws_sign::tests`) | SHA-256 and HMAC (RFC 4231) vectors, the AWS signing-key example, and a golden `Authorization` header. **The only tests that catch a signing regression**, because moto doesn't verify signatures. |
| Integration | `make integration` | The built `plugin.wasm` in a stock extism host against moto, checked through the AWS SDK. See [integration/README.md](../integration/README.md). |

```bash
docker run --rm -d -p 5000:5000 --name moto motoserver/moto:5.2.6
make integration                         # or MOTO_ENDPOINT=http://localhost:5055
```

The extism host in the integration tests may only reach the moto host, so a test
fails if the plugin tries to call real AWS.

**Before changing signing or the crypto dependencies**, the golden `Authorization`
header in `aws_sign.rs` must still match byte for byte. Only re-capture it if the
signed request format itself changes on purpose.

## CI

`.github/workflows/ci.yml` runs on every push and on PRs to `main`:

| Job | Runs |
|---|---|
| Unit tests | `cargo test --target <host>` |
| Build WASM | `cargo build --release --target wasm32-unknown-unknown` |
| Clippy | `cargo clippy --target <host> -- -D warnings` |
| Rustfmt | `cargo fmt --check` |
| Integration | builds `plugin.wasm`, starts `motoserver/moto:5.2.6` as a service, lints the harness, runs `cargo test` in `integration/` |

## Releasing

1. **Bump `version` in `Cargo.toml`** in its own PR (`chore: set version to X.Y.Z`).
   The plugin reports this version to deckwatch, so skipping the bump makes a new
   build look like the previous release.
2. Update [CHANGELOG.md](../CHANGELOG.md): move the *Unreleased* entries under the
   new version.
3. After merging, tag `main` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `.github/workflows/release.yml` builds `plugin.wasm` and attaches it to the
   GitHub Release, with generated notes.
5. Point deckwatch's plugin source at the new tag (see
   [Configuration](configuration.md#installing-the-plugin)).

## Dependencies

[Dependabot](../.github/dependabot.yml) proposes weekly updates for the plugin
crate, the integration harness and the GitHub Actions:

- **`hmac`, `sha2` and `digest` are grouped and always move together.** They share
  the `digest` trait crate, and upgrading only one fails to compile.
- **Minor and patch updates are grouped** per ecosystem, and the `aws-*` harness
  crates move in lockstep.

Dependabot can't see these container images; update them by hand:

| Image | Where |
|---|---|
| `motoserver/moto` | `.github/workflows/ci.yml`, `Makefile`, `integration/README.md`, this page |
| `amazon/aws-cli` | `DEFAULT_BOOTSTRAP_AWSCLI_IMAGE` in `src/lib.rs` |
| `postgres` | `DEFAULT_BOOTSTRAP_PSQL_IMAGE` in `src/lib.rs` |
