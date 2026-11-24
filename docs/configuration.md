# Configuration

This page covers installing the plugin in deckwatch, giving it AWS credentials,
the hosts it needs to reach, every config key, and the IAM permissions the
plugin's own role needs.

- [Installing the plugin](#installing-the-plugin)
- [Credentials](#credentials)
- [Allowed hosts](#allowed-hosts)
- [Config reference](#config-reference)
- [Plugin IAM permissions](#plugin-iam-permissions)

## Installing the plugin

deckwatch can load the plugin from a GitHub release, a URL, or an uploaded file.

**From a GitHub release (recommended for production):** release builds attach
`plugin.wasm` to each `v*` tag.

```json
{
  "name": "AWS",
  "enabled": true,
  "source": {
    "type": "github",
    "repo": "alexconrey/deckwatch-plugin-aws",
    "ref": "v0.7.2",
    "path": "plugin.wasm",
    "use_release": true
  }
}
```

**By upload (for testing a build before it's released):** the upload endpoint takes
the **raw WASM bytes as the request body**, not multipart form data. A
`-F file=@…` upload is rejected with `400 not a valid WASM binary`.

```bash
curl -X POST \
  -H 'Content-Type: application/wasm' \
  --data-binary @dist/plugin.wasm \
  https://<deckwatch-host>/api/plugins/AWS/upload
```

- `AWS` must match the plugin's name in deckwatch settings, and the plugin must
  already exist there.
- A successful upload returns `204 No Content`. deckwatch then reloads the plugin
  in the background.
- If deckwatch has API auth enabled, add `-H "Authorization: Bearer <token>"`.
- To confirm the new binary is the one loaded, see
  [Operations → Verifying the loaded binary](operations.md#verifying-the-loaded-binary).

## Credentials

The plugin resolves AWS credentials on every call, in this order:

1. **Workload identity (IRSA, recommended).** If the plugin config contains both
   `AWS_IDENTITY_TOKEN` and `AWS_ROLE_ARN`, the plugin exchanges the token for
   temporary credentials with STS `AssumeRoleWithWebIdentity`, at
   `sts.<AWS_REGION>.amazonaws.com`.
2. **Static keys.** `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, plus an optional
   `AWS_SESSION_TOKEN`.

The plugin has no filesystem access. To use deckwatch's own IRSA identity, tell
deckwatch to read the values from its pod environment when it calls the plugin:

```json
{
  "inherit_env_keys": ["AWS_ROLE_ARN", "AWS_REGION"],
  "inherit_env_file_keys": { "AWS_IDENTITY_TOKEN": "AWS_WEB_IDENTITY_TOKEN_FILE" }
}
```

`inherit_env_file_keys` reads the file named by the environment variable
`AWS_WEB_IDENTITY_TOKEN_FILE` and injects its contents as `AWS_IDENTITY_TOKEN`. The
plugin also uses `AWS_ROLE_ARN` to find the AWS account ID for the RDS
`rds-db:connect` policy.

deckwatch also injects `CURRENT_TIMESTAMP` on every call. WASM has no system clock,
and SigV4 request signing needs the current time. You don't need to set it.

## Allowed hosts

extism only lets the plugin reach hosts listed in the plugin's `allowed_hosts`. List
the endpoints for your region. Every service the plugin uses is shown below; leave
out the ones you don't use.

| Service | Commercial (`us-east-1` example) | GovCloud (`us-gov-west-1`) |
|---|---|---|
| IAM | `iam.amazonaws.com` | `iam.us-gov.amazonaws.com` |
| STS (IRSA) | `sts.us-east-1.amazonaws.com` | `sts.us-gov-west-1.amazonaws.com` |
| RDS | `rds.us-east-1.amazonaws.com` | `rds.us-gov-west-1.amazonaws.com` |
| S3 (per-bucket hostnames) | `*.s3.us-east-1.amazonaws.com` | `*.s3.us-gov-west-1.amazonaws.com` |
| SQS | `sqs.us-east-1.amazonaws.com` | `sqs.us-gov-west-1.amazonaws.com` |
| Secrets Manager | `secretsmanager.us-east-1.amazonaws.com` | `secretsmanager.us-gov-west-1.amazonaws.com` |
| AWS Backup | `backup.us-east-1.amazonaws.com` | `backup.us-gov-west-1.amazonaws.com` |

- S3 requests go to `<bucket>.s3.<region>.amazonaws.com` (virtual-hosted style, which
  GovCloud requires), so the S3 entry needs the `*.` wildcard.
- If you set `AWS_ENDPOINT_URL` (testing only), add that host as well.

## Config reference

Set these keys in the plugin's `config`. Defaults come from the plugin's
`metadata()`, so deckwatch shows them in the UI.

### Core

| Key | Default | Description |
|---|---|---|
| `AWS_REGION` | `us-east-1` | Region for API calls and provisioned resources. Selects the partition: `us-gov-*` uses GovCloud endpoints and `arn:aws-us-gov` ARNs. |
| `OIDC_PROVIDER_ARN` | *(none)* | ARN of the cluster's IAM OIDC provider, e.g. `arn:aws-us-gov:iam::<account>:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/<id>`. **Required for IRSA:** without it, workload roles get an empty trust policy and pods can't assume them. |
| `ROLE_PATH` | `/deckwatch-plugin/` | IAM path for every role the plugin creates. Must start and end with `/`. Scope the plugin's IAM permissions to this path. |
| `BUCKET_PREFIX` | *(empty)* | Prepended to every S3 bucket name, e.g. `myorg-` turns `uploads` into `myorg-uploads`. |
| `RESOURCE_NAME_PREFIX` | *(empty)* | Prepended to every SQS queue and Secrets Manager secret name, both defaults and names chosen in the UI, e.g. `k2-dw-` produces `k2-dw-<namespace>-<app>-queue`. It's never added twice. Set it so the plugin's IAM policy can be [scoped to `<prefix>*`](#scoping-sqs-and-secrets-manager-to-a-prefix) instead of every queue and secret in the account. |
| `RESOURCE_TAGS` | *(empty)* | Tags applied to every AWS resource the plugin manages: IAM roles, RDS instances (and their snapshots), S3 buckets, SQS queues, secrets and backup plans. Write them as `Key=Value` pairs separated by commas or newlines, e.g. `Team=platform,CostCenter=1234`. Validated against AWS's tag rules (at most 47 tags; no `aws:` or `deckwatch.io/` keys). See [Resource tags](#resource-tags). |

### Credentials

| Key | Description |
|---|---|
| `AWS_ROLE_ARN` + `AWS_IDENTITY_TOKEN` | IRSA credentials. Usually injected by deckwatch, see [Credentials](#credentials). |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | Static credentials (secret fields). Leave empty when using IRSA. |

### Endpoints

| Key | Default | Description |
|---|---|---|
| `IAM_ENDPOINT` | auto | IAM hostname override. Auto: `iam.us-gov.amazonaws.com` for `us-gov-*`, otherwise `iam.amazonaws.com`. Takes priority over `AWS_ENDPOINT_URL` for IAM. |
| `IAM_SIGNING_REGION` | auto | SigV4 signing region for IAM. Auto: `us-gov-west-1` for GovCloud, otherwise `us-east-1`. |
| `AWS_ENDPOINT_URL` | *(none)* | **Testing only.** Sends every AWS call to one `http(s)://host[:port]`, e.g. moto or LocalStack, and switches S3 to path-style addressing. A malformed value fails the call instead of falling back to AWS. Leave empty in production. |

### RDS

| Key | Default | Description |
|---|---|---|
| `RDS_DEFAULT_SUBNET_GROUP` | *(none)* | DB subnet group for new instances. Needed to place them in the right VPC. |
| `RDS_DEFAULT_SECURITY_GROUPS` | *(none)* | Comma-separated VPC security group IDs for new instances. |
| `RDS_DEFAULT_IAM_AUTH` | `true` | Enables IAM database auth on new instances unless the resource or annotation says otherwise. |
| `RDS_BACKUP_RETENTION_DAYS` | `14` | Days of automated backups (point-in-time recovery) to keep, 1–35. Existing instances below this are **raised** on reconcile and never lowered. `0` and invalid values fall back to 14; the plugin never disables backups. See [Operations → Backups](operations.md#backups). |
| `RDS_BACKUP_WINDOW` | *(RDS chooses)* | Daily backup window for new instances, `hh24:mi-hh24:mi` in UTC, at least 30 minutes. |
| `DB_BOOTSTRAP_AWSCLI_IMAGE` | `amazon/aws-cli:2.42.2` | Init-container image for the [IAM database user bootstrap Job](identity.md#rds-iam-authentication). |
| `DB_BOOTSTRAP_PSQL_IMAGE` | `postgres:19-alpine` | psql image for the bootstrap Job. Must be the same as, or newer than, the RDS engine major version. |

### MCP tuning hints

The plugin also declares MCP tuning fields. deckwatch's AI assistant uses them when
it suggests names: `rds_naming_convention`, `s3_bucket_prefix_convention`,
`iam_role_path` and `preferred_rds_instance_class`. They don't change plugin
behaviour.

## Plugin IAM permissions

The plugin's own credentials (the role in `AWS_ROLE_ARN`, or the static keys) need
the permissions below. The list comes from the API calls in `src/`. Replace
`<partition>` (`aws` or `aws-us-gov`), `<account>`, and the role path if you changed
`ROLE_PATH`. Drop the statements for services you don't use.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WorkloadRoles",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy",
        "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:DeleteRolePolicy", "iam:DeleteRole"
      ],
      "Resource": "arn:<partition>:iam::<account>:role/deckwatch-plugin/*"
    },
    {
      "Sid": "Rds",
      "Effect": "Allow",
      "Action": [
        "rds:CreateDBInstance", "rds:DescribeDBInstances", "rds:ModifyDBInstance",
        "rds:DeleteDBInstance", "rds:CreateDBSnapshot", "rds:AddTagsToResource"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RdsManagedMasterPassword",
      "Effect": "Allow",
      "Action": ["secretsmanager:CreateSecret", "secretsmanager:TagResource"],
      "Resource": "arn:<partition>:secretsmanager:*:<account>:secret:rds!*"
    },
    {
      "Sid": "S3",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket", "s3:PutBucketVersioning",
        "s3:PutBucketPublicAccessBlock", "s3:PutLifecycleConfiguration",
        "s3:GetBucketTagging", "s3:PutBucketTagging"
      ],
      "Resource": "arn:<partition>:s3:::*"
    },
    {
      "Sid": "Sqs",
      "Effect": "Allow",
      "Action": [
        "sqs:CreateQueue", "sqs:GetQueueUrl", "sqs:GetQueueAttributes",
        "sqs:DeleteQueue", "sqs:TagQueue"
      ],
      "Resource": "arn:<partition>:sqs:*:<account>:<RESOURCE_NAME_PREFIX>*"
    },
    {
      "Sid": "SecretsManager",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret", "secretsmanager:DescribeSecret",
        "secretsmanager:DeleteSecret", "secretsmanager:TagResource"
      ],
      "Resource": "arn:<partition>:secretsmanager:*:<account>:secret:<RESOURCE_NAME_PREFIX>*"
    },
    {
      "Sid": "Backup",
      "Effect": "Allow",
      "Action": ["backup:CreateBackupPlan", "backup:ListBackupPlans", "backup:CreateBackupSelection"],
      "Resource": "*"
    },
    {
      "Sid": "PassBackupRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "<backup-role-arn>",
      "Condition": { "StringEquals": { "iam:PassedToService": "backup.amazonaws.com" } }
    }
  ]
}
```

Notes:
- **Why `PutRolePolicy` on workload roles is enough:** every permission the plugin
  grants to workloads is an inline policy on a role under `ROLE_PATH`. The plugin
  never attaches managed policies and never touches other roles.
- **RDS managed passwords:** instances are created with `ManageMasterUserPassword`,
  so RDS creates the master secret on the plugin's behalf. Hence the
  `secretsmanager:CreateSecret` on `rds!*` secrets. If you use a customer-managed
  KMS key, the plugin also needs `kms:DescribeKey`, `kms:CreateGrant` and
  `kms:GenerateDataKey` on it.
- **`iam:PassRole`** is only needed if you schedule snapshots with AWS Backup. Scope
  it to the role in `rds.deckwatch.io/backup-role-arn`.
- **Trust for `AssumeRoleWithWebIdentity`** goes on the plugin role's trust policy,
  for deckwatch's ServiceAccount, not in this permissions policy.
- **Tagging permissions:** `iam:TagRole`, `rds:AddTagsToResource`,
  `s3:Get/PutBucketTagging`, `sqs:TagQueue`, `secretsmanager:TagResource` and
  `backup:TagResource` are needed when [resource tags](#resource-tags) are applied.
  The managed `deckwatch.io/*` tags are always applied. AWS also requires the
  tagging permission for tags passed *at creation*, e.g. `sqs:TagQueue` for
  `CreateQueue` with tags.

### Scoping SQS and Secrets Manager to a prefix

Granting the SQS and Secrets Manager actions on every queue or secret would let
deckwatch change unrelated ones, such as a Karpenter interruption queue or
application credentials. Set `RESOURCE_NAME_PREFIX` (for example `k2-dw-`)
instead, and scope those statements to `…:<prefix>*` as shown above. Every
queue and secret the plugin creates carries the prefix, including names entered
in the UI.

Changing the prefix after queues or secrets exist makes reconciles create *new*
prefixed resources for annotation-based queues, so choose it before first use.

## Resource tags

Every AWS resource the plugin manages gets `RESOURCE_TAGS` plus three managed
tags, which configuration can't override:

| Tag | Value |
|---|---|
| `deckwatch.io/managed-by` | `deckwatch-plugin-aws` |
| `deckwatch.io/application` | the application name |
| `deckwatch.io/namespace` | the application's namespace |

| Resource | On create | Existing resources (every reconcile) |
|---|---|---|
| IAM role | `CreateRole` tags | `TagRole` |
| RDS instance | `CreateDBInstance` tags (copied to snapshots) | `AddTagsToResource` |
| S3 bucket | merged into the bucket's tag set | merged; tags set by others are kept |
| SQS queue | `CreateQueue` tags | `TagQueue` |
| Secret | `CreateSecret` tags | `TagResource` |
| AWS Backup plan | `CreateBackupPlan` tags | (not re-tagged) |

Tagging only adds or updates the plugin's keys. Other tags on a resource are left
alone, and removing a key from `RESOURCE_TAGS` doesn't remove it from existing
resources. If `RESOURCE_TAGS` is invalid, the plugin applies only the managed
tags and reports the problem as a provisioning warning. Tagging failures are
warnings too; they never block provisioning.
