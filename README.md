# deckwatch-plugin-aws

A [deckwatch](https://github.com/alexconrey/deckwatch) plugin that provisions
**IAM roles, RDS instances, and S3 buckets** for Kubernetes workloads using a
single unified IAM role per workload.

## Why one plugin for three services?

Each workload gets exactly one IAM role. Policies for RDS and S3 are attached as
inline policies on that role, keeping IAM state minimal and auditable. The plugin
creates or verifies the role first, then applies whatever resource policies are
needed — operators never have to manage cross-service IAM wiring manually.

## Prerequisites

- [deckwatch](https://github.com/alexconrey/deckwatch) operator running in your cluster.
- AWS credentials configured in `PluginConfig.config` (see [Configuration](#configuration)).
- For RDS IAM auth: an OIDC provider configured for your EKS cluster.
- For AWS Backup snapshots: an IAM role that `backup.amazonaws.com` can assume, with
  permissions to create snapshots of the target RDS instance.

## Capabilities provided

This plugin declares the following capability IDs in its `metadata()` export:

```
aws:iam-role         — IAM role created for this workload
aws:service-account  — ServiceAccount with IRSA annotation applied to the pod
aws:rds-connection   — RDS instance provisioned
aws:s3-bucket        — S3 bucket provisioned
```

Downstream plugins can declare `depends_on: ["aws:iam-role"]` to run after this
plugin and read its outputs.

## Configuration

In your deckwatch `PluginConfig`, set the following keys under `config`:

| Key | Required | Description |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | Yes | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Yes | AWS secret key |
| `AWS_SESSION_TOKEN` | No | Session token (for temporary credentials) |
| `AWS_REGION` | No | Default AWS region (falls back to `us-east-1`) |
| `BUCKET_PREFIX` | No | Prepended to every bucket name, e.g. `"myorg-"` |

## Annotation reference

### Global — `aws.deckwatch.io/`

| Annotation | Example | Notes |
|---|---|---|
| `aws.deckwatch.io/enabled` | `"true"` | Master opt-in. Also implied by any rds/s3 annotation. |
| `aws.deckwatch.io/role-name` | `"myapp-role"` | Optional. Defaults to `<namespace>-<deployment>-role`. |

### RDS — `rds.deckwatch.io/`

| Annotation | Example | Notes |
|---|---|---|
| `rds.deckwatch.io/enabled` | `"true"` | Must be set to provision an RDS instance. |
| `rds.deckwatch.io/engine` | `"postgres"` | `"postgres"` (default) or `"mysql"`. |
| `rds.deckwatch.io/instance-class` | `"db.t3.micro"` | Default: `db.t3.micro`. |
| `rds.deckwatch.io/allocated-storage` | `"20"` | GiB. Default: `20`. |
| `rds.deckwatch.io/identifier` | `"myapp-db"` | RDS instance identifier. Defaults to `<ns>-<deploy>-db` (max 63 chars). |
| `rds.deckwatch.io/db-name` | `"app"` | Initial database name. Default: `"app"`. |
| `rds.deckwatch.io/multi-az` | `"false"` | Enable Multi-AZ. Default: `false`. |
| `rds.deckwatch.io/subnet-group` | `"my-subnet-group"` | Optional DB subnet group. |
| `rds.deckwatch.io/security-groups` | `"sg-abc,sg-def"` | Comma-separated VPC security group IDs. |
| `rds.deckwatch.io/iam-auth` | `"true"` | Use IAM database authentication. Injects `DB_IAM_AUTH=true`. |
| `rds.deckwatch.io/snapshot-schedule` | `"cron(0 3 * * ? *)"` | AWS EventBridge cron for AWS Backup. Enables snapshot scheduling. |
| `rds.deckwatch.io/snapshot-retention` | `"7"` | AWS Backup retention days. Default: `7`. |
| `rds.deckwatch.io/backup-role-arn` | `"arn:aws:iam::…:role/backup"` | IAM role for `backup.amazonaws.com`. |

### S3 — `s3.deckwatch.io/`

| Annotation | Example | Notes |
|---|---|---|
| `s3.deckwatch.io/enabled` | `"true"` | Must be set to provision a bucket. |
| `s3.deckwatch.io/bucket-name` | `"assets"` | Name suffix. Final name is `{BUCKET_PREFIX}{bucket-name}`. |
| `s3.deckwatch.io/region` | `"us-east-1"` | Bucket region. Default: `us-east-1`. |
| `s3.deckwatch.io/versioning` | `"true"` | Enable object versioning. Default: `false`. |
| `s3.deckwatch.io/public-access-block` | `"true"` | Block all public access. Default: `true`. |
| `s3.deckwatch.io/lifecycle-days` | `"90"` | Expire objects after N days. |

## Example deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-api
  namespace: production
  annotations:
    aws.deckwatch.io/enabled: "true"
    rds.deckwatch.io/enabled: "true"
    rds.deckwatch.io/engine: "postgres"
    rds.deckwatch.io/instance-class: "db.t3.small"
    rds.deckwatch.io/db-name: "api"
    rds.deckwatch.io/iam-auth: "true"
    rds.deckwatch.io/snapshot-schedule: "cron(0 3 * * ? *)"
    rds.deckwatch.io/snapshot-retention: "14"
    rds.deckwatch.io/backup-role-arn: "arn:aws:iam::123456789012:role/aws-backup"
    s3.deckwatch.io/enabled: "true"
    s3.deckwatch.io/bucket-name: "uploads"
    s3.deckwatch.io/versioning: "true"
spec:
  # ...
```

### What the plugin injects

For the deployment above, the plugin:

1. Creates IAM role `production-my-api-role` (or finds the existing one).
2. Creates a `ServiceAccount` with an IRSA annotation pointing to that role.
3. Provisions RDS instance `production-my-api-db` (postgres, db.t3.small).
4. Attaches an `rds-db:connect` inline policy to the role.
5. Creates an AWS Backup plan with a daily snapshot schedule (cron 03:00 UTC)
   and 14-day retention.
6. Creates S3 bucket `{BUCKET_PREFIX}uploads` with versioning enabled.
7. Attaches `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`
   inline policy for that bucket to the role.
8. Injects the following env vars into the pod's primary container:

   ```
   DB_ENGINE=postgres
   DB_PORT=5432
   DB_NAME=api
   DB_IAM_AUTH=true
   DB_HOST=production-my-api-db.xxxx.us-east-1.rds.amazonaws.com
   S3_BUCKET=myorg-uploads
   S3_REGION=us-east-1
   AWS_REGION=us-east-1
   ```

## IAM trust policy

The role is created with a broad EKS trust policy. **Operators should replace
this with their OIDC provider ARN** to follow the principle of least privilege:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<account>:oidc-provider/<oidc-url>"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "<oidc-url>:sub": "system:serviceaccount:<namespace>:<sa-name>"
      }
    }
  }]
}
```

Support for injecting a scoped trust policy via annotation is planned.

## S3 bucket prefix

The `BUCKET_PREFIX` plugin config key is prepended to every bucket name. This
lets one deckwatch installation share a single plugin config across multiple
environments while keeping bucket names globally unique:

```
BUCKET_PREFIX=prod-myorg-
s3.deckwatch.io/bucket-name=uploads
→ S3_BUCKET=prod-myorg-uploads
```

## AWS Backup snapshots

Snapshot scheduling uses AWS Backup rather than a Kubernetes `CronJob`. This
means no cluster-side pod is needed for snapshots, reducing operational surface
area. The backup plan is created idempotently on each reconcile — running the
plugin multiple times for the same deployment is safe.

The `rds.deckwatch.io/backup-role-arn` annotation must point to an IAM role
that `backup.amazonaws.com` can assume and that has at minimum:

```json
{
  "Effect": "Allow",
  "Action": ["rds:CreateDBSnapshot", "rds:DescribeDBSnapshots", "backup:*"],
  "Resource": "*"
}
```

## Plugin outputs

Downstream plugins can read the following keys from `ctx.plugin_outputs["aws"]`:

| Key | Description |
|---|---|
| `role_arn` | Full ARN of the workload IAM role |
| `service_account_name` | Name of the created ServiceAccount |
| `rds_endpoint` | RDS hostname (empty while instance is provisioning) |
| `s3_bucket` | Full bucket name (prefix applied) |

## Building

Requirements: Rust stable + `wasm32-unknown-unknown` target.

```bash
rustup target add wasm32-unknown-unknown
make build   # produces dist/plugin.wasm
make test    # run unit tests on the host target
```

## Releasing

Push a `v*` tag to trigger the GitHub Actions release workflow, which builds the
WASM artifact and attaches it to the GitHub Release. The deckwatch operator
fetches the artifact URL from the release.

## License

Apache-2.0
