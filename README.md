# interop-verifier

`interop-verifier` is a generalized Sally-style KERIpy verifier used by the
`keri-ts` ACDC interop tests. It receives normal CESR/IPEX credential
presentations, verifies them with KERIpy VDR state, and posts generic webhook
payloads without hardcoding the vLEI credential chain.

## Install

```sh
uv tool install interop-verifier
```

## Run from PyPI

```sh
interop-verifier start \
  --name verifier \
  --base "" \
  --alias verifier \
  --http 9723 \
  --web-hook http://127.0.0.1:9923/
```

The verifier uses a bundled no-witness inception config by default. Pass
`--incept-file` to use a custom KERIpy-style inception JSON file.

Pass `--protocol-version 1.0` or `--protocol-version 2.0` to select the KERI
protocol and CESR genus for inception, ingress, and signed OOBI replies. The
selection also applies when reopening existing state. Omitting it follows the
installed KERIpy default; ingress no longer unconditionally assumes v1. Use
`--protocol-version 1.0` for the current v1 IPEX presentation workflow. Released
KERIpy 1.2.x retains its native v1 behavior and rejects an explicit v2 request.
The v2 selector covers current-main ingress and OOBIs; it does not add v2 IPEX
credential presentation support to KERIpy.

## Run with Docker

```sh
docker run --rm -p 9723:9723 kentbull/interop-verifier:1.0.0 start \
  --name verifier \
  --head-dir /data \
  --alias verifier \
  --http 9723 \
  --web-hook http://host.docker.internal:9923/
```

Mount `/data` to persist verifier key state.

## Interfaces

The verifier serves:

- `GET /health` for liveness and queue counts.
- `GET /oobi/{aid}/controller` for KERI controller OOBI resolution.
- `PUT /` and `POST /` for CESR/KERI ingress.
- Sally-style signed webhook callbacks for verified credentials.

## Development

```sh
make sync
make check
make build
make docker-build
```
