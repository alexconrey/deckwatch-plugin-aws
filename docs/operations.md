# Operations

- [Upgrading the plugin](#upgrading-the-plugin)
- [Verifying the loaded binary](#verifying-the-loaded-binary)
- [Refreshing a resource](#refreshing-a-resource)
- [Backups](#backups)
- [Removing a resource](#removing-a-resource)
- [Granting access by hand](#granting-access-by-hand)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)

## Upgrading the plugin

**Read the new version's *Upgrade notes* in the [CHANGELOG](../CHANGELOG.md)
first.** They list the IAM permissions and settings the plugin's role and config
need before the new binary runs. 0.8.0, for example, can't create workload roles
without `iam:TagRole`.

**If the notes say existing resources change** (0.8.0 raises RDS backup
retention, tags every resource and rewrites inline policies), back up before
upgrading:

- Take a manual snapshot of each plugin-managed RDS instance, and wait until it's
  `available` before upgrading. Manual snapshots don't expire with the retention
  window. Snapshot identifiers allow only letters, digits and hyphens (starting
  with a letter, with no double hyphens), so write the version's dots as
  hyphens and add a date. Tag values may contain dots:

  ```bash
  aws rds create-db-snapshot --db-instance-identifier <id> \
    --db-snapshot-identifier <id>-pre-v0-8-0-<yyyymmdd> \
    --tags Key=Purpose,Value=pre-plugin-upgrade-v0.8.0
  aws rds wait db-snapshot-available \
    --db-snapshot-identifier <id>-pre-v0-8-0-<yyyymmdd>
  ```

- Record what to roll back to: the loaded binary's version, `sha256` and source
  (see [Verifying the loaded binary](#verifying-the-loaded-binary)), and the
  plugin's config.
- Save the workload roles' inline policies with `aws iam get-role-policy`.

Rolling back the binary stops further changes but doesn't undo the ones already
made in AWS.

1. **Release builds:** bump the release `ref` in the plugin's GitHub source. deckwatch
   fetches the new `plugin.wasm` and reloads it.
2. **Unreleased builds** (for example, testing a fix): upload the binary. The
   endpoint takes the raw bytes, not form data:

   ```bash
   make build
   shasum -a 256 dist/plugin.wasm
   curl -X POST -H 'Content-Type: application/wasm' \
     --data-binary @dist/plugin.wasm \
     https://<deckwatch-host>/api/plugins/AWS/upload        # → 204 No Content
   ```

   - Uploading switches the plugin's source to `upload: AWS.wasm`. Switch it back to
     the GitHub release once the fix is released.
   - On deckwatch versions without
     [alexconrey/deckwatch#209](https://github.com/alexconrey/deckwatch/pull/209),
     an upload unloads every *other* plugin until deckwatch next reloads all plugins
     (a restart or a settings save).

Upgrading the plugin changes nothing in AWS by itself. New behaviour applies the next
time a resource is provisioned or refreshed, or a deployment is reconciled.

**Upgrading from a version before 0.8.0:**
- Refresh each S3, SQS and Secrets Manager resource once. Those versions attached
  no IAM policy when provisioning them, so the application got `AccessDenied`.
  Refreshing attaches the policy and stamps the annotations that keep it in place.
- Queues and secrets that already exist keep their names. If you set
  `RESOURCE_NAME_PREFIX`, refreshing one creates a **new**, prefixed queue or secret
  and points the application at it. The application loses access to the old one,
  which is left in place, so drain the queue or copy the secret's value across.
  To keep the existing names, leave the prefix empty. The plugin's SQS and Secrets
  Manager permissions then can't be scoped to a prefix.

## Verifying the loaded binary

The plugin reports its version as `metadata().version`, taken from `Cargo.toml`.
**An unreleased build can report the same version as a release**, so compare
checksums instead. deckwatch builds that include
[alexconrey/deckwatch#206](https://github.com/alexconrey/deckwatch/pull/206) report
the SHA-256 of the bytes they actually loaded:

```bash
curl -s https://<deckwatch-host>/api/plugins | jq '.[] | select(.name=="AWS") | {version, sha256, loaded_at}'
```

The MCP `list_plugins` and `get_plugin_config` tools return the same fields. The
`sha256` must match `shasum -a 256` of the file you uploaded or released.

## Refreshing a resource

deckwatch's `refresh_resource` (MCP) or the UI equivalent re-runs `provision()` with
the original form fields. Use it to pick up plugin fixes, for example to stamp new
annotations or re-attach a policy, or to unstick a resource left in
`DB_STATUS=provisioning`.

**Refreshing can restart the application's pods.** If the result changes the
deployment annotations or injected env vars, deckwatch patches every deployment in
the application. The pod templates change, so Kubernetes rolls the pods. With one
replica and the default rollout settings, expect a short outage while the new pods
start. Refresh outside busy periods.

## Backups

Every RDS instance the plugin manages is backed up **daily** by RDS automated
backups:

| | Default | Controlled by |
|---|---|---|
| Retention / point-in-time recovery window | **14 days** | `RDS_BACKUP_RETENTION_DAYS` (1–35) |
| Backup window | chosen by RDS | `RDS_BACKUP_WINDOW` (new instances) |
| Snapshot tags | copied from the instance | always on |
| After the instance is deleted | automated backups **kept** until they expire, plus a final snapshot | always on |

- **Existing instances are brought up to the setting.** On every reconcile (a
  deployment update or a resource refresh), an instance whose retention is below
  `RDS_BACKUP_RETENTION_DAYS` is raised to it. Changing between two non-zero values
  doesn't cause an outage. Instances created before this behaviour existed have
  RDS's API default of **1 day**, and are raised the next time they're reconciled.
  Retention is never lowered.
- **Instances with backups disabled (retention 0) aren't changed automatically.**
  Re-enabling backups can cause a brief outage, so the plugin reports a warning
  instead. Re-enable them during a maintenance window.
- **AWS Backup schedules** (`rds.deckwatch.io/snapshot-schedule`, see
  [AWS Backup snapshots](identity.md#aws-backup-snapshots)) add scheduled snapshots
  with their own retention. They're optional, and only available through
  annotations for now.

To check an instance:

```bash
aws rds describe-db-instances --db-instance-identifier <id> \
  --query 'DBInstances[0].{retentionDays:BackupRetentionPeriod,window:PreferredBackupWindow,latestRestorable:LatestRestorableTime}'
aws rds describe-db-snapshots --db-instance-identifier <id> --snapshot-type automated \
  --query 'DBSnapshots[].SnapshotCreateTime'
```

`LatestRestorableTime` should be within the last few minutes, and there should be one
automated snapshot per day, going back as many days as the retention setting.

## Removing a resource

**Data is never deleted without a way to get it back.** Every resource is
snapshotted or kept:

| Resource | On removal |
|---|---|
| RDS | **Always** takes a final snapshot, `<identifier>-final-YYYYMMDD-HHMMSS`, then turns off deletion protection and deletes the instance. Its automated backups are kept until their retention expires. There's no option to skip the snapshot. |
| S3 | **Keeps the bucket and its objects**, because S3 has no snapshots. The removal message includes the commands to delete it once you're sure. |
| SQS | Deletes the queue **only if it's empty** (no visible, in-flight or delayed messages). A queue with messages is kept, along with the app's access, so it can be drained. |
| Secrets Manager | Schedules deletion with a 30-day recovery window. Restore it from the console or CLI within that window if needed. |

Then the plugin cleans up IAM:

- It removes the resource's inline policy (for example `deckwatch-sqs-access`) from
  the app's workload role.
- It deletes the workload role once **nothing** is left on it: no inline policies
  from other resources or annotations, and no attached managed policies. Removing
  one of several resources keeps the shared role.
- Removing RDS also deletes the DB bootstrap Job's role,
  `<namespace>-<app>-rds-bootstrap`.
- If a resource was kept because deletion failed or was refused (an RDS error, or a
  queue with messages), its policy is kept too.

The removal message lists every snapshot taken, everything kept, and every IAM
change.

## Granting access by hand

Sometimes an application needs access before the plugin can grant it, for example
while new plugin permissions are still being rolled out. Add your own inline policy
to the application's workload role, `<namespace>-<app>-rds`:

- **Use your own policy name**, such as `manual-<purpose>`. Never use one of the
  plugin's `deckwatch-*` names: the plugin replaces those on every reconcile.
- **Create the resource under the name the plugin will use**, including
  `RESOURCE_NAME_PREFIX` (see [naming](resources.md#naming-defaults)).
  Provisioning then adopts it instead of creating another one. An existing secret
  is adopted as is, value included.
- **Grant only what the plugin would.** For a secret the plugin will own, that's
  `secretsmanager:GetSecretValue`, `DescribeSecret` and `PutSecretValue` on
  `arn:<partition>:secretsmanager:<region>:<account>:secret:<name>-??????`. Secrets
  Manager adds six random characters to every secret ARN.
- **Remove the policy once the plugin's policy covers the access**, after the
  resource is provisioned or refreshed. While the policy exists, the role isn't
  empty, so removing the application's last resource keeps the role.

```bash
aws secretsmanager create-secret --name '<prefix><namespace>/<app>'
aws iam put-role-policy --role-name <namespace>-<app>-rds \
  --policy-name manual-<purpose> --policy-document file://policy.json
# Once the plugin has provisioned the resource:
aws iam delete-role-policy --role-name <namespace>-<app>-rds --policy-name manual-<purpose>
```

## Troubleshooting

### `AccessDenied` from the application

1. **Find the pod's identity:** check its `serviceAccountName`. It should be
   `<app>-aws-sa`, and the pod should have an `aws-iam-token` volume. If it runs as
   `default`, it has no AWS identity at all; see the next section.
2. **Check the role's policies:**
   `aws iam list-role-policies --role-name <role>`. Each resource should have its
   policy from [the table](identity.md#inline-policies). If an S3, SQS or Secrets
   Manager resource has none, it was probably provisioned by a version before
   0.8.0. Refresh it.
3. **Check the ARNs:** `aws iam get-role-policy …`. In GovCloud every ARN must start
   with `arn:aws-us-gov:`.
4. **Confirm what's allowed:**
   `aws iam simulate-principal-policy --policy-source-arn <role-arn> --action-names s3:GetObject --resource-arns arn:<partition>:s3:::<bucket>/x`
   shows whether the role itself allows the action. If it does, look at the resource
   side next: bucket policies, KMS key policies, VPC endpoint policies.

### Provisioning fails with `AccessDenied` for the plugin's own role

If the error names deckwatch's role (`AWS_ROLE_ARN`) rather than the
application's, the plugin's own permissions are missing something. Compare the
action and resource in the message with
[Plugin IAM permissions](configuration.md#plugin-iam-permissions):

- **A queue or secret name without your prefix:** `RESOURCE_NAME_PREFIX` isn't set,
  or doesn't match the `<prefix>*` the policy is scoped to.
- **A tagging action** (`iam:TagRole`, `rds:AddTagsToResource`, `sqs:TagQueue`,
  `secretsmanager:TagResource`): grant it. Every create call carries tags, so
  without it the create fails.
- **`iam:GetRole` or `iam:ListRolePolicies` on `role/<name>`, without the path:**
  these lookups must be granted on `role/*`. IAM authorizes calls on a role that
  doesn't exist without its path.

### `can't find the specified secret value for staging label: AWSCURRENT`

The secret exists but has no value yet. The plugin creates secrets empty. Set the
first value from a pod that runs as the application's ServiceAccount, as shown in
[Secrets Manager secret](resources.md#secrets-manager-secret-secretsmanager).

### The pod runs as `default` instead of `<app>-aws-sa`

- **No AWS opt-in:** the deployment needs annotations that enable the plugin. Look
  for `aws.deckwatch.io/*`, `rds.deckwatch.io/enabled` or `s3.deckwatch.io/enabled`
  on the deployment.
- **Role creation failed:** the plugin skips the ServiceAccount when `ensure_role`
  fails. Check the plugin's logs in deckwatch.
- **Applied to some deployments but not others:** if some deployments in an
  application get the ServiceAccount and others don't, despite identical
  annotations, the cause is on the deckwatch side, in how `wants_service_account`
  is applied.

### Pods can't assume the role

The role's trust policy must name
`system:serviceaccount:<namespace>:<app>-aws-sa` and the cluster's OIDC provider. An
empty trust policy means `OIDC_PROVIDER_ARN` wasn't set when the role was created.
Set it, and the next reconcile updates the trust policy.

### RDS is stuck at `DB_STATUS=provisioning`

Instance creation takes several minutes. If it stays stuck, check the instance in
the RDS console and refresh the resource. The IAM role, ServiceAccount and bootstrap
Job are only created once the instance reports an endpoint.

### IAM database login fails

- Check the bootstrap Job `<app>-db-bootstrap` in the application's namespace.
- `DB_BOOTSTRAP_PSQL_IMAGE` must be the same as, or newer than, the engine's major
  version.

### Plugin calls fail with a host error

The endpoint is missing from the plugin's `allowed_hosts`. See
[Allowed hosts](configuration.md#allowed-hosts).

## Known limitations

- **The ServiceAccount isn't deleted when the role is.** deckwatch doesn't yet let
  plugins delete Kubernetes objects; `deprovision()` can only return errors and a
  message. When the last resource's removal deletes the role, the message tells you
  to delete `<app>-aws-sa` with `kubectl`. The DB bootstrap Job and its
  ServiceAccount stay as well. SDK v0.10.0, which the plugin uses, adds
  `delete_kubernetes_resources` for this. The plugin will use it once deckwatch
  supports it
  ([alexconrey/deckwatch#235](https://github.com/alexconrey/deckwatch/pull/235),
  in review).
- **Removing an application's last resource leaves its annotations on the
  deployments.** deckwatch only re-applies resource annotations to applications
  that still have resources, so `apply()` keeps seeing the old
  `*.deckwatch.io/*` annotations and could, for example, re-create an empty SQS
  queue. Remove the annotations, or redeploy without them.
  [alexconrey/deckwatch#229](https://github.com/alexconrey/deckwatch/pull/229)
  (in review) fixes this in deckwatch.
- **`RESOURCE_TAGS` is a single text field in the deckwatch UI.** A row-per-tag
  editor needs deckwatch support for the SDK's `key_value` field type. The plugin
  already accepts the JSON form that field will store.
- **The workload role keeps the `-rds` suffix** even when it carries other
  resources' policies. Renaming it would orphan existing roles.
- **Annotation-only roles aren't cleaned up.** Roles created purely from
  annotations (`<namespace>-<app>-role`) have no provisioned resource to remove.
- **The IAM database user bootstrap is PostgreSQL-only.**
- **China regions** need `IAM_ENDPOINT` set by hand.
