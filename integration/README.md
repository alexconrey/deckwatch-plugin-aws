# Integration tests

These tests run the compiled `dist/plugin.wasm` in a stock
[extism](https://extism.org) host against a [moto](https://github.com/getmoto/moto)
AWS emulator. They call the plugin's real WASM exports (`provision`, `apply`)
with the JSON deckwatch sends, then check the resulting AWS state with the
official AWS SDK. Because the SDK is independent of the plugin's own request
and SigV4 code, a bug there can't make a test pass by accident.

The extism manifest only allows HTTP to the moto host, so a request to real
`*.amazonaws.com` is blocked and fails the test.

## What's covered

All tests are in [`tests/end_to_end.rs`](tests/end_to_end.rs), in commercial and
GovCloud regions:

- **S3:** provisioning grants the app's role (creating the role if needed), `apply()`
  re-asserts the policy and ServiceAccount, and `BUCKET_PREFIX` is applied once.
- **SQS:** provisioning and annotations grant queue access. Removal keeps a queue
  that still has messages.
- **Secrets Manager:** provisioning grants access, and removal schedules deletion
  and cleans up IAM.
- **Shared role:** removing one of several resources keeps the role until the last
  one goes.
- **RDS:** new instances get 14-day backup retention, existing instances are
  raised on reconcile, and removal always takes a final snapshot.
- **Naming and tags:** `RESOURCE_NAME_PREFIX` scopes queue and secret names, and
  `RESOURCE_TAGS` plus the managed tags reach every resource type.
- **AWS Backup:** a snapshot schedule creates a tagged backup plan.
- **Safety:** a malformed `AWS_ENDPOINT_URL` fails instead of reaching AWS.

## What moto doesn't check

- **Signatures.** The known-answer tests in `src/aws_sign.rs` cover signing.
- **IAM permissions.** Every call is allowed, so these tests can't show that the
  documented [plugin IAM policy](../docs/configuration.md#plugin-iam-permissions)
  is complete.
- **`CreateBackupSelection`.** moto 5.2.6 returns HTTP 500 for it, and the AWS CLI
  gets the same error. The AWS Backup test therefore checks the plan and its tags,
  not the selection.

## Running locally

```bash
docker run --rm -d -p 5000:5000 --name moto motoserver/moto:5.2.6
make integration                  # builds plugin.wasm, then runs the tests
```

Use another port with `make integration MOTO_ENDPOINT=http://localhost:5055`.

Requires Rust 1.96+, because extism 1.41 depends on wasmtime 49.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `MOTO_ENDPOINT` | `http://localhost:5000` | moto server URL; passed to the plugin as `AWS_ENDPOINT_URL` |
| `PLUGIN_WASM` | `../dist/plugin.wasm` | plugin build under test |

## How the plugin reaches moto

The plugin's `AWS_ENDPOINT_URL` config key sends every AWS API call to one
`http(s)://host[:port]`, and switches S3 to path-style addressing. If the value
is malformed, provisioning fails rather than falling back to real AWS. Leave the
key unset in production.

## Writing tests

- Give AWS resources names from `unique(...)`. Tests share one moto server and
  run in parallel, and the run-specific suffix also keeps reruns against a
  long-lived server from colliding.
- Load the plugin with `load_plugin(region, &[(key, value)])` to add config keys,
  and call it with `call_provision`, `call_apply` and `call_deprovision`.
- Check results through the AWS SDK clients (`iam_client`, `s3_client`,
  `sqs_client`, `secrets_client`, `rds_client`, `backup_client`), not through the
  plugin's own output alone. `inline_policy` and `policy_resources` read a role's
  policy back.
- Mutation-check a new test: break the fix on purpose and confirm the test fails.
