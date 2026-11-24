# Resources and annotations

The plugin creates AWS resources two ways:

- **Provisioning (recommended):** an operator adds a resource to a deckwatch
  Application in the UI or over MCP. deckwatch calls the plugin's `provision()` once,
  stores the result as application-level state, and injects that state into **every
  deployment and cronjob in the application** as environment variables.
- **Annotations:** the plugin's `apply()` runs on every deployment create and update,
  and acts on `*.deckwatch.io/*` annotations. This path also re-asserts IAM policies
  on each reconcile.

Provisioning stamps the annotations that `apply()` needs, so a provisioned resource
stays reconciled automatically.

- [Provisionable resources](#provisionable-resources): `rds`, `s3`, `sqs`, `secretsmanager`
- [Annotation reference](#annotation-reference)
- [Environment variables](#environment-variables)
- [Naming defaults](#naming-defaults)
- [Plugin outputs and capabilities](#plugin-outputs-and-capabilities)

## Provisionable resources

These are the resources deckwatch shows under **Add resource**. Form fields are
listed with their defaults.

### RDS database (`rds`)

| Field | Default | Notes |
|---|---|---|
| `identifier` | `<namespace>-<app>-db` | RDS instance identifier (at most 63 characters). |
| `engine` | `postgres` | `postgres` or `mysql`. |
| `instance_class` | `db.t3.micro` | |
| `db_name` | `app` | Initial database. |
| `iam_auth` | `RDS_DEFAULT_IAM_AUTH` (default `true`) | IAM database authentication. |

What gets created:
- **An instance** that is encrypted (gp3), not publicly accessible, has **deletion
  protection** on, uses 20 GiB of storage and is single-AZ. Its master user is
  `dbadmin`, with a password managed by RDS in Secrets Manager. It's placed using
  `RDS_DEFAULT_SUBNET_GROUP` and `RDS_DEFAULT_SECURITY_GROUPS`.
- **Polling while it starts:** while the instance is being created, the state is
  `DB_STATUS=provisioning` and deckwatch keeps polling.
- **With IAM auth, once it's available:**
  - the workload role `<namespace>-<app>-rds` with an `rds-db:connect` policy
  - the `<app>-aws-sa` ServiceAccount
  - for PostgreSQL, a one-shot [bootstrap Job](identity.md#rds-iam-authentication)
    that creates the IAM database user `<app>`

### S3 bucket (`s3`)

| Field | Default | Notes |
|---|---|---|
| `bucket_name` | *(required)* | `BUCKET_PREFIX` is prepended. |
| `region` | plugin `AWS_REGION` | Bucket region. |

What gets created:
- The bucket, with public access blocked.
- The `deckwatch-s3-access` inline policy (object get, put and delete, plus list) on
  the application's workload role, `<namespace>-<app>-rds`. That role is created if
  RDS hasn't already created it.
- The `<app>-aws-sa` ServiceAccount.
- The annotations `s3.deckwatch.io/{enabled,bucket-name,region}`, so every reconcile
  re-asserts the policy.

### SQS queue (`sqs`)

| Field | Default | Notes |
|---|---|---|
| `queue_name` | `<namespace>-<app>-queue` | `.fifo` is appended for FIFO queues. |
| `fifo` | `false` | FIFO with content-based deduplication. |
| `visibility_timeout` | `30` | Seconds. |
| `retention_days` | `4` | Days, at most 14. |

What gets created:
- The queue.
- The `deckwatch-sqs-access` inline policy on the app's workload role,
  `<namespace>-<app>-rds`.
- The `<app>-aws-sa` ServiceAccount.
- The `sqs.deckwatch.io/*` annotations, so every reconcile re-asserts the policy.

### Secrets Manager secret (`secretsmanager`)

| Field | Default | Notes |
|---|---|---|
| `secret_name` | `<namespace>/<app>` | Name or path. |

What gets created:
- An **empty** secret. Populate the value yourself or from CI.
- The `deckwatch-secretsmanager-access` inline policy (`GetSecretValue` and
  `DescribeSecret` on that secret) on the app's workload role.
- The `<app>-aws-sa` ServiceAccount.
- A `secretsmanager.deckwatch.io/secret-arns` annotation. It grants access without
  `enabled`, so reconciles re-assert read access but never create another secret.

## Annotation reference

Any `rds`, `s3`, `sqs`, `ecr` or `secretsmanager` opt-in also implies
`aws.deckwatch.io/enabled`. When the plugin is active for a deployment, it ensures
the workload role exists and binds the pods to `<app>-aws-sa`.

### Global (`aws.deckwatch.io/`)

| Annotation | Default | Notes |
|---|---|---|
| `aws.deckwatch.io/enabled` | `false` | Master opt-in, for an IAM role and ServiceAccount with no other resources. |
| `aws.deckwatch.io/app-name` | see [Naming defaults](#naming-defaults) | Logical application name. Keys the shared role and ServiceAccount, so every deployment of one app uses the same identity. |
| `aws.deckwatch.io/role-name` | `<namespace>-<app>-role` | Workload role name. Provisioning sets this to `<namespace>-<app>-rds`. |

### RDS

| Annotation | Default | Notes |
|---|---|---|
| `rds.deckwatch.io/enabled` | `false` | Opt in. |
| `rds.deckwatch.io/identifier` | `<namespace>-<deployment>-db` | Instance identifier. |
| `rds.deckwatch.io/engine` | `postgres` | `postgres` or `mysql`. |
| `rds.deckwatch.io/instance-class` | `db.t3.micro` | |
| `rds.deckwatch.io/allocated-storage` | `20` | GiB. |
| `rds.deckwatch.io/db-name` | `app` | |
| `rds.deckwatch.io/multi-az` | `false` | |
| `rds.deckwatch.io/subnet-group` | `RDS_DEFAULT_SUBNET_GROUP` | |
| `rds.deckwatch.io/security-groups` | `RDS_DEFAULT_SECURITY_GROUPS` | Comma-separated. |
| `rds.deckwatch.io/iam-auth` | `RDS_DEFAULT_IAM_AUTH` | Attaches `rds-db:connect` for user `<app>` once the instance exists. |
| `rds.deckwatch.io/snapshot-schedule` | *(none)* | AWS Backup cron, e.g. `cron(0 3 * * ? *)`. See [AWS Backup](identity.md#aws-backup-snapshots). |
| `rds.deckwatch.io/snapshot-retention` | `7` | Days. |
| `rds.deckwatch.io/backup-role-arn` | *(none)* | Role that `backup.amazonaws.com` assumes. Required with a schedule. |

RDS instances are always created in the plugin's `AWS_REGION`.

### S3

| Annotation | Default | Notes |
|---|---|---|
| `s3.deckwatch.io/enabled` | `false` | Opt in. |
| `s3.deckwatch.io/bucket-name` | *(required)* | Name **without** `BUCKET_PREFIX`; the prefix is added. |
| `s3.deckwatch.io/region` | `us-east-1` | Bucket region. Set it explicitly in GovCloud. |
| `s3.deckwatch.io/versioning` | `false` | |
| `s3.deckwatch.io/public-access-block` | `true` | Blocks all public access. |
| `s3.deckwatch.io/lifecycle-days` | *(none)* | Expire objects after N days. |

### SQS

| Annotation | Default | Notes |
|---|---|---|
| `sqs.deckwatch.io/enabled` | `false` | Opt in. Attaches `deckwatch-sqs-access`. |
| `sqs.deckwatch.io/queue-name` | `<namespace>-<deployment>-queue` | |
| `sqs.deckwatch.io/fifo` | `false` | |
| `sqs.deckwatch.io/visibility-timeout` | `30` | Seconds. |
| `sqs.deckwatch.io/retention-days` | `4` | Days, at most 14. |

### ECR

| Annotation | Default | Notes |
|---|---|---|
| `ecr.deckwatch.io/enabled` | `false` | Attaches `deckwatch-ecr-pull` (ECR auth token plus layer and image pull on all repositories). |

### Secrets Manager

| Annotation | Default | Notes |
|---|---|---|
| `secretsmanager.deckwatch.io/secret-arns` | *(none)* | Comma-separated ARNs of existing secrets to grant `GetSecretValue` and `DescribeSecret` on. |
| `secretsmanager.deckwatch.io/enabled` | `false` | Also create a managed (empty) secret and grant access to it. |
| `secretsmanager.deckwatch.io/secret-name` | `<namespace>/<deployment>` | Name for the created secret. |

### Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
  annotations:
    aws.deckwatch.io/app-name: "shop"
    rds.deckwatch.io/enabled: "true"
    rds.deckwatch.io/identifier: "shop-db"
    rds.deckwatch.io/db-name: "shop"
    s3.deckwatch.io/enabled: "true"
    s3.deckwatch.io/bucket-name: "shop-uploads"
    s3.deckwatch.io/region: "us-gov-west-1"
    sqs.deckwatch.io/enabled: "true"
    sqs.deckwatch.io/queue-name: "shop-orders"
```

The pods run as `shop-aws-sa`, bound to the role `shop-shop-role`. That role has
`deckwatch-rds-connect` (user `shop`), `deckwatch-s3-access` and
`deckwatch-sqs-access` attached.

## Environment variables

| Resource | Variables |
|---|---|
| RDS | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_ENGINE`, `DB_STATUS` (`provisioning` / `available`), `DB_IAM_AUTH`, and the PostgreSQL-style aliases `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`. Provisioning also records `DB_ROLE_ARN` and `DB_SA_NAME`. |
| S3 | `S3_BUCKET` (prefix applied), `S3_REGION`, `AWS_REGION`. Provisioning also records `S3_ROLE_ARN` and `S3_SA_NAME`. |
| SQS | `QUEUE_URL`, `QUEUE_NAME`. Provisioning also records `SQS_ROLE_ARN` and `SQS_SA_NAME`. |
| Secrets Manager | `SM_SECRET_ARN`, `SM_SECRET_NAME`. Provisioning also records `SM_ROLE_ARN` and `SM_SA_NAME`. |

`POSTGRES_USER` is the IAM database user (`<app>`) when IAM auth is on; otherwise it's
the master user `dbadmin`. With IAM auth, generate a token at runtime instead of
using a password. For example, with SQLAlchemy:
`postgresql+psycopg2://${POSTGRES_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}` plus an
IAM token as the password.

## Naming defaults

| Thing | Provisioning | Annotations |
|---|---|---|
| App name | the deckwatch application name | `aws.deckwatch.io/app-name`, then the `app.kubernetes.io/name` label, then the `app` label, then the deployment name |
| Workload role | `<namespace>-<app>-rds` | `aws.deckwatch.io/role-name`, else `<namespace>-<app>-role` |
| ServiceAccount | `<app>-aws-sa` | `<app>-aws-sa` |
| RDS identifier | `<namespace>-<app>-db` | `<namespace>-<deployment>-db` |
| SQS queue | `<namespace>-<app>-queue` | `<namespace>-<deployment>-queue` |
| Secret | `<namespace>/<app>` | `<namespace>/<deployment>` |

The `-rds` role suffix is historical: RDS was the first resource to create the role.
S3 attaches to the same role so that an application keeps a single identity.

## Plugin outputs and capabilities

`apply()` publishes these outputs. Downstream plugins read them from
`ctx.plugin_outputs["aws"]`.

| Key | Value |
|---|---|
| `role_arn` | Workload role ARN (empty if role creation failed) |
| `service_account_name` | `<app>-aws-sa` |
| `rds_endpoint`, `db_status` | RDS hostname and status, when RDS is enabled |
| `s3_bucket` | Full bucket name |
| `queue_url` | SQS queue URL |
| `sm_secret_arn` | ARN of the created secret |

Capabilities declared in `metadata().provides`, for other plugins'
`depends_on`: `aws:iam-role`, `aws:service-account`, `aws:rds-connection`,
`aws:s3-bucket`, `aws:sqs-queue`, `aws:secret-access`, `aws:ecr-pull`.
