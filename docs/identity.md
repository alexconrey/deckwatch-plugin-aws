# Identity and IAM

Every application gets **one IAM role and one Kubernetes ServiceAccount**. Each
resource the application uses adds one **inline policy** to that role, scoped to
that resource. The plugin never attaches managed policies and never modifies roles
outside `ROLE_PATH`. To audit an application's AWS access, list one role's inline
policies.

- [Workload role and ServiceAccount](#workload-role-and-serviceaccount)
- [Trust policy](#trust-policy)
- [Inline policies](#inline-policies)
- [GovCloud and partitions](#govcloud-and-partitions)
- [RDS IAM authentication](#rds-iam-authentication)
- [AWS Backup snapshots](#aws-backup-snapshots)

## Workload role and ServiceAccount

| | Name | Created by |
|---|---|---|
| IAM role | `<namespace>-<app>-rds` when provisioned (see [naming](resources.md#naming-defaults)), under `ROLE_PATH` (default `/deckwatch-plugin/`) | `provision()` for RDS (IAM auth) and S3; `apply()` on reconcile |
| ServiceAccount | `<app>-aws-sa`, annotated `eks.amazonaws.com/role-arn: <role ARN>` | `provision()` returns it as a Kubernetes resource; `apply()` asks deckwatch for it with `wants_service_account` |

- **The ServiceAccount is only requested once the role exists.** If role creation
  fails, `apply()` still injects env vars but leaves the pod's ServiceAccount alone.
  This avoids binding pods to a ServiceAccount whose role doesn't exist, which would
  break every AWS call.
- **The role is shared across the app.** All deployments of an application share the
  role and ServiceAccount, keyed by the [app name](resources.md#naming-defaults).

## Trust policy

When `OIDC_PROVIDER_ARN` is set, every workload role trusts **only its own
ServiceAccount**:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws-us-gov:iam::<account>:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/<id>" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.us-gov-west-1.amazonaws.com/id/<id>:sub": "system:serviceaccount:<namespace>:<app>-aws-sa",
        "oidc.eks.us-gov-west-1.amazonaws.com/id/<id>:aud": "sts.amazonaws.com"
      }
    }
  }]
}
```

- **Kept current on every reconcile:** the plugin calls `UpdateAssumeRolePolicy` each
  time, so setting `OIDC_PROVIDER_ARN` later fixes roles that were created without it.
- **Without `OIDC_PROVIDER_ARN`,** roles get an empty trust policy, and nothing can
  assume them. The plugin logs a warning.

## Inline policies

| Policy name | Added when | Grants | Resource |
|---|---|---|---|
| `deckwatch-rds-connect` | RDS with IAM auth, once the instance exists | `rds-db:connect` | `arn:<partition>:rds-db:<region>:<account>:dbuser:<DbiResourceId>/<app>` |
| `deckwatch-s3-access` | S3 | `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` / `s3:ListBucket` | `arn:<partition>:s3:::<bucket>/*` / `arn:<partition>:s3:::<bucket>` |
| `deckwatch-sqs-access` | SQS (provisioned, or `sqs.deckwatch.io/enabled`) | Send, Receive, Delete, ChangeMessageVisibility, GetQueueUrl, GetQueueAttributes | `arn:<partition>:sqs:<region>:<account>:<queue>` |
| `deckwatch-secretsmanager-access` | Secrets Manager (provisioned, or `secretsmanager.deckwatch.io/*`) | `GetSecretValue`, `DescribeSecret` | the listed secret ARNs, plus any secret it created |
| `deckwatch-ecr-pull` | `ecr.deckwatch.io/enabled` | `GetAuthorizationToken`, `BatchCheckLayerAvailability`, `GetDownloadUrlForLayer`, `BatchGetImage` | `*` |

`PutRolePolicy` replaces a policy of the same name, so the plugin can re-apply
policies on every reconcile safely. deckwatch allows at most one resource of each
type per application, so one fixed policy name per type never collides. Removing a
resource deletes its policy, and the role is deleted with the last policy (see
[Removing a resource](operations.md#removing-a-resource)). If someone deletes a policy by hand, the next
reconcile restores it.

## GovCloud and partitions

The partition is chosen from the region, for both endpoints and ARNs:

| Region prefix | Partition | IAM endpoint (signing region) |
|---|---|---|
| `us-gov-` | `aws-us-gov` | `iam.us-gov.amazonaws.com` (`us-gov-west-1`) |
| `cn-` | `aws-cn` | (set `IAM_ENDPOINT`) |
| anything else | `aws` | `iam.amazonaws.com` (`us-east-1`) |

Every ARN the plugin writes into a policy or AWS Backup selection uses that
partition. A policy that names `arn:aws:…` in GovCloud is valid but matches
nothing, so the plugin builds them all from the region. S3 uses virtual-hosted
addressing (`<bucket>.s3.<region>.amazonaws.com`) and sends
`x-amz-content-sha256` on every request; GovCloud requires both.

## RDS IAM authentication

With IAM auth, the application connects as a database user named `<app>`,
authenticating with a short-lived token instead of a password.

```mermaid
sequenceDiagram
    participant P as provision()
    participant RDS
    participant K as Kubernetes
    participant J as Bootstrap Job
    P->>RDS: CreateDBInstance (IAM auth, managed master password)
    Note over P,RDS: deckwatch re-polls until the instance is available
    P->>RDS: DescribeDBInstances (endpoint, DbiResourceId, master secret ARN)
    P->>P: workload role + deckwatch-rds-connect
    P->>K: <app>-aws-sa, <app>-db-bootstrap SA + Job
    J->>J: init: read master secret (Secrets Manager)
    J->>RDS: CREATE ROLE <app> LOGIN; GRANT rds_iam; grants
```

- **Why a Job:** RDS only creates the master user, and WASM can't open a database
  connection. So once the instance is available, `provision()` emits a ServiceAccount
  and a one-shot Job, both named `<app>-db-bootstrap`.
- **Least privilege:** the Job's own role, `<namespace>-<app>-rds-bootstrap`, can
  only read this instance's master secret. The workload role never can.
- **The password never leaves the Job:** an init container (`DB_BOOTSTRAP_AWSCLI_IMAGE`)
  fetches the secret into a memory-backed `emptyDir`. The psql container
  (`DB_BOOTSTRAP_PSQL_IMAGE`) runs idempotent `CREATE ROLE … LOGIN`, `GRANT rds_iam`,
  and database and `public` schema grants, then deletes the file. The password never
  enters plugin state, a Kubernetes Secret, or the Job spec.
- **Re-runs:** the Job name includes a hash of its spec, so changing an image or
  setting starts a new Job on the next provision. The SQL is safe to repeat.
- **PostgreSQL only.** For MySQL, create the IAM user yourself.

## AWS Backup snapshots

Set `rds.deckwatch.io/snapshot-schedule` (EventBridge cron) together with
`rds.deckwatch.io/backup-role-arn` on a deployment. The plugin then:

1. finds or creates a backup plan named `<identifier>-backup` with rule
   `scheduled-snapshot`, using the `Default` vault and deleting after
   `snapshot-retention` days. It lists existing plans first, because
   `CreateBackupPlan` isn't idempotent.
2. creates the selection `<identifier>-selection` for the instance's ARN. "Already
   exists" counts as success.

The backup role must trust `backup.amazonaws.com`. Attaching the AWS managed policy
`AWSBackupServiceRolePolicyForBackup` to it is the usual approach. The plugin's own
credentials need `iam:PassRole` on that role (see
[Plugin IAM permissions](configuration.md#plugin-iam-permissions)). Snapshot
scheduling creates no Kubernetes resources; it lives entirely in AWS Backup.
