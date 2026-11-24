# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/). Entries before 0.7.2 were reconstructed from the git
history.

## [Unreleased]

### Added
- `RDS_BACKUP_RETENTION_DAYS` (default **14**, range 1–35) and `RDS_BACKUP_WINDOW`
  config keys.
- `RESOURCE_NAME_PREFIX`: prepended to every SQS queue and Secrets Manager secret
  name, so the plugin's IAM policy can be scoped to `<prefix>*` instead of every
  queue and secret in the account.
- `RESOURCE_TAGS`: `Key=Value` tags applied to every managed resource (IAM roles,
  RDS, S3, SQS, secrets, backup plans) on create and on every reconcile. Also
  adds the managed `deckwatch.io/managed-by`, `deckwatch.io/application` and
  `deckwatch.io/namespace` tags. S3 tags are merged, so existing bucket tags are
  kept.

### Changed
- **RDS instances keep 14 days of automated backups by default**, instead of RDS's
  API default of 1 day. Existing instances below the setting are raised on
  reconcile (no outage between non-zero values). Retention is never lowered, and
  disabled backups are reported rather than re-enabled automatically. Snapshots
  copy instance tags.
- Deleting an RDS instance keeps its automated backups until they expire
  (`DeleteAutomatedBackups=false`), in addition to the final snapshot.
- **Removing a resource never destroys data without a recovery path.**
  - RDS always takes a final snapshot, now timestamped
    (`<identifier>-final-YYYYMMDD-HHMMSS`) so repeat deletions can't collide.
  - SQS queues that still hold messages are kept, along with the app's access.
  - S3 buckets are kept.
  - Secrets keep a 30-day recovery window.
- **Removing a resource cleans up IAM.** Its inline policy is removed from the
  workload role, and the role (and, for RDS, the bootstrap Job's role) is deleted
  once nothing is left on it.

### Fixed
- **AWS Backup snapshot schedules now create a backup plan.** The plugin sent
  `CreateBackupPlan` and `CreateBackupSelection` as `POST`, with a
  `"BackupPlanData"` body and the JSON-RPC content type. AWS Backup's REST-JSON
  API expects `PUT`, `"BackupPlan"` and `application/json`, so no plan was ever
  created.
- S3 bucket-configuration `PUT`s (tagging, lifecycle, versioning, public access
  block) now send `Content-MD5`, the message integrity header S3 requires on
  these operations.
- Secret names and descriptions are JSON-escaped when creating secrets.
- **Provisioned SQS queues and Secrets Manager secrets now grant the workload
  access.** They attach `deckwatch-sqs-access` / `deckwatch-secretsmanager-access`
  to the app role, emit the ServiceAccount, and stamp annotations so every reconcile
  re-asserts the grant.
- **Secrets Manager and AWS Backup responses are parsed as JSON**, instead of by
  `"key":"` substring matching. Responses with whitespace previously failed, and
  Secrets Manager's numeric `DeletionDate` showed as "unknown".
- **Provisioning an S3 bucket now grants the workload access to it.** `provision("s3")`
  never attached an IAM policy, and the S3 policy used `arn:aws:s3:::` ARNs, which
  never match GovCloud buckets. It now attaches `deckwatch-s3-access` with the
  correct partition to the application's role, emits the ServiceAccount, and stamps
  annotations so every reconcile keeps the policy in place. (#24)
- **SQS queues are created.** `GetQueueUrl` on a missing queue returns HTTP 400,
  which was treated as a hard failure, so annotation-based SQS never created queues. (#29)
- **GovCloud ARNs for SQS and AWS Backup.** Queue and RDS ARNs were hardcoded to the
  `aws` partition. Queue URLs in legacy and emulator form are now parsed as well. (#29)

### Added
- `AWS_ENDPOINT_URL` config key, for running against moto or LocalStack (testing
  only; fails closed when malformed). (#24)
- End-to-end integration tests that run `plugin.wasm` against moto in CI, covering
  S3 and SQS on GovCloud and commercial regions. (#24, #29)
- SigV4 known-answer tests. (#28)
- Dependabot for cargo and GitHub Actions. (#25, #28)
- Documentation set under `docs/`. Rewritten README.

### Changed
- DB bootstrap Job images: `amazon/aws-cli:2.42.2`, `postgres:19-alpine`. (#25)
- `hmac` 0.13 and `sha2` 0.11. Request signatures are byte-identical. (#28)
- GitHub Actions moved to their Node 24 releases. (#25)

### Removed
- The `RDS_SKIP_FINAL_SNAPSHOT` config key. RDS deletion always takes a final
  snapshot.
- The `rds.deckwatch.io/region` annotation. It was parsed but never used; RDS always
  uses `AWS_REGION`. (#29)

## [0.7.2] - 2026-11-06
### Fixed
- Escape Kubernetes `$(VAR)` expansion in the DB bootstrap Job. (#23)

## [0.7.1] - 2026-11-06
### Added
- Provisioning RDS with IAM auth creates the IAM database user with a one-shot
  bootstrap Job that reads the RDS-managed master secret. (#21)

## [0.7.0] - 2026-11-06
### Added
- `provision()` creates the workload IRSA role for RDS IAM auth.
- `POSTGRES_*` env vars alongside `DB_*`.
### Fixed
- RDS provisioning uses plugin config for networking and IAM-auth defaults.
- Provisioning stamps `rds.deckwatch.io/enabled` so `apply()` takes over.
- The ServiceAccount is only requested after the IAM role exists.

## [0.6.0] - 2026-09-18
### Added
- One IRSA ServiceAccount per application (`<app>-aws-sa`), with idempotent
  annotation upsert.
- MCP tuning fields in `metadata()`.

## [0.5.0] - 2026-08-13
### Added
- SQS, ECR and Secrets Manager. (#16)
### Fixed
- IRSA trust policy, scoped to the workload's ServiceAccount via
  `OIDC_PROVIDER_ARN`; AWS Backup idempotency. (#16)

## [0.4.0] - 2026-08-13
### Added
- `deployment_annotations` for S3 and RDS. (#15)
### Fixed
- GovCloud S3: virtual-hosted addressing, `x-amz-content-sha256` signing. (#15)

## [0.3.4] - 2026-08-12
### Fixed
- Clock: use deckwatch's `now()` host function instead of an STS HTTP round-trip. (#12)

## [0.3.3] - 2026-08-12
### Fixed
- Restore `config_schema` and resource helpers on host builds, and add regression
  tests. (#11)

## [0.3.2] - 2026-08-12
### Added
- `provision()` export with `rds` and `s3` resource declarations. (#9)

## [0.3.0] - 2026-08-12
### Changed
- Errors are reported through `result.errors` instead of only being logged. (#8)

## [0.2.4] - 2026-08-12
### Fixed
- Partition-aware IAM endpoint with a configurable override. (#7)

## [0.2.3] - 2026-08-12
### Added
- `ROLE_PATH` config key. (#6)

## [0.2.2] - 2026-08-12
### Fixed
- Create roles under `/deckwatch-plugin/`. (#5)

## [0.2.1] - 2026-08-12
### Fixed
- WASM clock: use the HTTP `Date` header instead of `SystemTime::now()`. (#4)

## [0.2.0] - 2026-08-11
### Added
- IRSA credentials via STS `AssumeRoleWithWebIdentity`. (#3)

## [0.1.0] - 2026-08-11
### Added
- Initial release: unified IAM role, RDS, S3, and AWS Backup snapshot scheduling. (#1)

[Unreleased]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.7.2...HEAD
[0.7.2]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.3.0...v0.3.2
[0.3.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/alexconrey/deckwatch-plugin-aws/releases/tag/v0.1.0
