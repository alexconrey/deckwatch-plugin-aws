# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/). Entries before 0.7.2 were reconstructed from the git
history.

## [Unreleased]

### Upgrade notes
- **Optional:** grant `iam:GetRolePolicy`, `s3:GetBucketVersioning`,
  `s3:GetBucketPublicAccessBlock`, `s3:GetLifecycleConfiguration` and
  `sqs:ListQueueTags`, so reconciles can skip writes when nothing changed.
  Without them, the plugin writes exactly as 0.8.0 did.
- **`BUCKET_PREFIX` is deprecated.** Set `RESOURCE_NAME_PREFIX` to the same
  value, then clear `BUCKET_PREFIX`. While it's set, it still names buckets,
  and provisioning warns.
- **Setting `RESOURCE_NAME_PREFIX` no longer renames existing queues, secrets
  or buckets.** The plugin finds them under their old names, which takes read
  access to them (`sqs:GetQueueUrl`, `secretsmanager:DescribeSecret`,
  `s3:GetBucketTagging`). Grant those explicitly before scoping the plugin's
  permissions to `<prefix>*`.

### Changed
- `deckwatch-plugin-sdk` v0.10.0, the tagged release, replaces the pre-release
  commit 0.8.0 was built with. No behaviour change: deckwatch receives the same
  metadata and results, because the SDK's new fields are empty and left out of
  the JSON. (#42)
- `md-5` is now a wasm32 dependency plus a dev-dependency, which clears cargo's
  "unused dependency" warning on host builds. (#44)
- **Reconciles skip AWS writes when nothing changed.** deckwatch can call
  `apply()` every few seconds. Each reconcile now compares before it writes and
  writes only what differs. That covers IAM trust policies, tags and inline
  policies; RDS tags; S3 bucket existence, public access block, versioning,
  lifecycle and tags; SQS tags; and secret tags. Most reconciles are now reads
  only. (#46)
- **`RESOURCE_NAME_PREFIX` also names new S3 buckets**, when `BUCKET_PREFIX` is
  empty and the prefix is a valid start of a bucket name. One prefix now covers
  queues, secrets and buckets, and the plugin's S3 permissions can be scoped to
  `<prefix>*` too. (#43)
- **Existing resources keep their names when the prefix is set later.** Refresh
  and reconcile find a queue, secret or bucket under its old, unprefixed name
  and keep using it, and provisioning reports that. 0.8.0 created new,
  prefixed resources instead. (#43)

### Deprecated
- `BUCKET_PREFIX`; use `RESOURCE_NAME_PREFIX`. (#43)

### Fixed
- The backup guidance's example snapshot name (`<id>-pre-v<version>`) isn't a
  valid RDS identifier once the version has dots. The docs now use
  `<id>-pre-v0-8-0-<yyyymmdd>` and show waiting for `available`. (#45)
- The "bucket tags already correct" check compared tag order as well as
  content, so unchanged bucket tags could be rewritten on every reconcile.
  (#46)
- Secrets Manager `DescribeSecret` and `DeleteSecret` requests are built with
  `serde_json`, so secret names are JSON-escaped. (#46)
- Removing a secret created before `RESOURCE_NAME_PREFIX` was set targeted a
  prefixed name that didn't exist. Deprovisioning now removes the recorded
  secret. (#43)

## [0.8.0] - 2026-11-24

### Upgrade notes
- **Back up before upgrading.** 0.8.0 changes existing resources on reconcile:
  it raises RDS backup retention, tags every resource and rewrites inline
  policies. Take a manual snapshot of each plugin-managed RDS instance, and
  record the loaded binary's `sha256` and the plugin config so you can roll
  back. See [docs/operations.md](docs/operations.md#upgrading-the-plugin).
- **New plugin IAM permissions.** Grant these before relying on the new
  behaviour; [docs/configuration.md](docs/configuration.md#plugin-iam-permissions)
  has the full policy:
  - `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies` (on `role/*`),
    `iam:DeleteRolePolicy`, `iam:DeleteRole` (on the role path);
  - tagging: `iam:TagRole`, `rds:AddTagsToResource`, `s3:GetBucketTagging`,
    `s3:PutBucketTagging`, `sqs:TagQueue`, `secretsmanager:TagResource`,
    `backup:TagResource`. **These are required.** Every create call now
    carries tags, and AWS denies a create whose tags the caller can't apply.
    Without `iam:TagRole`, workload roles aren't created at all;
  - SQS and Secrets Manager actions scoped to `RESOURCE_NAME_PREFIX`, including
    `sqs:GetQueueAttributes` for the empty-queue check.
- **Refresh S3, SQS and Secrets Manager resources provisioned by earlier
  versions** once after upgrading. That attaches the IAM policy they were
  missing (see *Fixed*) and stamps the annotations that keep it in place.
- **Set `RESOURCE_NAME_PREFIX` before provisioning any SQS queue or secret.**
  Existing queues and secrets aren't renamed. Once a prefix is set, the next
  refresh or reconcile creates a new, prefixed one, points the app at it and
  moves its access. The old one is left in place, so drain the queue or copy the
  secret's value first.
- **RDS deletion always takes a final snapshot.** `RDS_SKIP_FINAL_SNAPSHOT` is
  gone, and existing settings for it are ignored.
- **Existing RDS instances below `RDS_BACKUP_RETENTION_DAYS` (default 14) are
  raised on their next reconcile**, without an outage. Instances created by
  earlier versions have 1 day.
- **Provisioning or refreshing a resource can restart the application's pods**,
  because deckwatch re-applies the stamped annotations.

### Added
- **`RESOURCE_NAME_PREFIX`**: prepended to every SQS queue and Secrets Manager
  secret name, so the plugin's IAM policy can be scoped to `<prefix>*` instead of
  every queue and secret in the account. (#37)
- **`RESOURCE_TAGS`**: tags applied to every managed resource (IAM roles, RDS, S3,
  SQS, secrets, backup plans) on create and on every reconcile, plus the managed
  `deckwatch.io/managed-by`, `deckwatch.io/application` and
  `deckwatch.io/namespace` tags. S3 tags are merged, so existing bucket tags are
  kept. Accepts `Key=Value` lists or the JSON object a deckwatch `key_value` field
  stores. (#37)
- **Apps can write their own secrets.** A secret the plugin creates for an app
  also grants `PutSecretValue`, so pods using the app's ServiceAccount can set
  its value via `SM_SECRET_ARN`. Secrets referenced with `secret-arns` stay
  read-only. (#38)
- `RDS_BACKUP_RETENTION_DAYS` (default **14**, range 1–35) and
  `RDS_BACKUP_WINDOW`. (#32)
- `AWS_ENDPOINT_URL`, for running against moto or LocalStack (testing only;
  fails closed when malformed). (#24)
- End-to-end integration tests that run `plugin.wasm` against moto in CI (S3,
  SQS, Secrets Manager, RDS, tags, AWS Backup); SigV4 known-answer tests;
  Dependabot for cargo and GitHub Actions. (#24, #25, #28, #29, #31, #32, #37)
- Documentation set under `docs/`, rewritten README, and this changelog. (#30)

### Changed
- **Removing a resource never destroys data without a recovery path.**
  - RDS always takes a timestamped final snapshot
    (`<identifier>-final-YYYYMMDD-HHMMSS`) and keeps its automated backups.
  - S3 buckets are kept.
  - SQS queues that still hold messages are kept, along with the app's access.
  - Secrets keep a 30-day recovery window.

  (#31, #32)
- **Removing a resource cleans up IAM.** Its inline policy is removed from the
  workload role, and the role (and the RDS bootstrap role) is deleted once
  nothing is left on it. (#31)
- **RDS instances keep 14 days of automated backups by default**, instead of the
  API default of 1 day. Existing instances are raised on reconcile and never
  lowered; disabled backups are reported, not re-enabled. Snapshots copy instance
  tags. (#32)
- DB bootstrap Job images: `amazon/aws-cli:2.42.2`, `postgres:19-alpine`. (#25)
- `hmac` 0.13 and `sha2` 0.11 (signatures byte-identical), plus `md-5` for S3
  `Content-MD5`. GitHub Actions moved to their Node 24 releases. (#25, #28, #37)
- **Reproducible builds.** `Cargo.lock` is committed for the plugin and the
  integration harness. CI, the release workflow and the Makefile build with
  `--locked`, and CI fails if a lockfile is out of sync with its `Cargo.toml`.
  `deckwatch-plugin-sdk` is pinned to a commit instead of following its `main`
  branch. A release now builds exactly what CI tested. (#40)

### Fixed
- **Provisioning a resource now grants the workload access to it.** Before this,
  S3, SQS and Secrets Manager provisioning attached no IAM policy. (#24, #31)
- **GovCloud ARNs.** S3, SQS and AWS Backup ARNs were hardcoded to the `aws`
  partition and matched nothing in GovCloud. (#24, #29)
- **SQS queues are created.** A missing queue's HTTP 400 was treated as a hard
  failure. (#29)
- **AWS Backup snapshot schedules create a plan.** Requests used `POST`, a
  `"BackupPlanData"` body and the JSON-RPC content type instead of REST-JSON. (#37)
- **S3 bucket-configuration `PUT`s send `Content-MD5`**, which S3 requires. (#37)
- **Secrets Manager and AWS Backup responses are parsed as JSON**, which fixes
  responses containing whitespace and the numeric `DeletionDate`. Secret create
  requests are escaped. (#31, #37)
- **Deprovisioning lists a role's policies before deleting them.** With
  path-scoped IAM grants, deleting a policy from an already-deleted role returned
  AccessDenied. (#36)

### Removed
- The `RDS_SKIP_FINAL_SNAPSHOT` config key. (#31)
- The unused `rds.deckwatch.io/region` annotation. (#29)

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

[Unreleased]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/alexconrey/deckwatch-plugin-aws/compare/v0.7.2...v0.8.0
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
