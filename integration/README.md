# Integration tests

These tests run the compiled `dist/plugin.wasm` in a stock
[extism](https://extism.org) host against a [moto](https://github.com/getmoto/moto)
AWS emulator. They call the plugin's real WASM exports (`provision`, `apply`)
with the JSON deckwatch sends, then check the resulting AWS state with the
official AWS SDK. Because the SDK is independent of the plugin's own request
and SigV4 code, a bug there can't make a test pass by accident.

The extism manifest only allows HTTP to the moto host, so a request to real
`*.amazonaws.com` is blocked and fails the test.

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
- Check results through the AWS SDK clients (`iam_client`, `s3_client`), not
  through the plugin's own output alone.
