# interop-verifier

`interop-verifier` is a generalized Sally-style KERIpy verifier used by the
`keri-ts` ACDC interop tests. It receives normal CESR/IPEX credential
presentations, verifies them with KERIpy VDR state, and posts generic webhook
payloads without hardcoding the vLEI credential chain.

## Run

```sh
interop-verifier start \
  --name verifier \
  --base "" \
  --alias verifier \
  --http 9723 \
  --web-hook http://127.0.0.1:9923/ \
  --incept-file scripts/interop-verifier-incept-no-wits.json
```

The verifier serves `/health`, controller OOBIs, and root CESR ingress.
