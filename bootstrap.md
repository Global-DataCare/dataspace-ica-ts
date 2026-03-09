# Bootstrap and CA Activation Guide

This guide separates controller bootstrap, ICA signing bootstrap, and CA submission packaging.

## 1) Controller Bootstrap (`controller:bootstrap`)

Generate deterministic controller key material and member DID artifacts:

```bash
node ./bin/ica-cli.js controller:bootstrap \
  --domain ica.example.com \
  --email it-director@example.org \
  --jurisdiction ES \
  --role-isco 1120 \
  --sector management \
  --alg ES384 \
  --scrypt 17:8:1:48 \
  --salt ica-controller-salt-v1 \
  --passphrase "replace-with-strong-passphrase" \
  --out-dir output/controller-bootstrap
```

Outputs:
- `controller-private-key.pem`
- `controller-public-jwk.json`
- `controller.csr.pem`
- `controller-did.json` (+ hosted `publish/<did-path>/did.json`)
- `controller.env` (`ICA_SELF_CONTROLLER_*`)

## 2) ICA Signing Bootstrap (`ica:bootstrap`)

Generate deterministic ICA VC-signing key material and ICA DID artifacts:

```bash
node ./bin/ica-cli.js ica:bootstrap \
  --domain ica.example.com \
  --jurisdiction ES \
  --scope onehealth:ica \
  --alg ES384 \
  --scrypt 17:8:1:48 \
  --salt ica-signing-salt-v1 \
  --passphrase "replace-with-strong-passphrase" \
  --controller-dir output/controller-bootstrap \
  --out-dir output/ica-bootstrap
```

Outputs:
- `ica-signing-private-key.pem`
- `ica-signing-public-jwk.json`
- `ica-signing.csr.pem`
- `ica-did.json` (+ hosted `publish/.well-known/did.json`)
- `ica.env` (seed env with `ICA_VC_PRIVATE_KEY_SEED_CONFIG` + `ICA_VC_PRIVATE_KEY_SEED_SALT`)
- `activate-request.template.json` (canonical `body.data[]` format)

`--controller-dir` is optional, but recommended so ICA DID can reference controller DID consistently.

## 3) CA Submission Bundle (`ca:prepare-submission`)

Prepare one bucket-ready folder with both controller and ICA artifacts:

```bash
node ./bin/ica-cli.js ca:prepare-submission \
  --controller-dir output/controller-bootstrap \
  --ica-dir output/ica-bootstrap \
  --request-id req-es-20260307-001 \
  --out-dir output/ca-submission
```

Resulting folder:
- `controller/controller.csr.pem`
- `controller/controller-did.json`
- `controller/controller-public-jwk.json`
- `ica/ica-signing.csr.pem`
- `ica/ica-did.json`
- `ica/ica-signing-public-jwk.json`
- `ica/activate-request.template.json` (if available)
- `manifest.json`

## 4) Runtime Bootstrap Env (deterministic flow, salt separated)

```bash
ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=replace-with-strong-passphrase
ICA_VC_PRIVATE_KEY_SEED_CONFIG=17:8:1:48
ICA_VC_PRIVATE_KEY_SEED_SALT=ica-seed-salt-v1
ICA_VC_SEED_ALG=ES384
```

`ICA_VC_SIGNING_KEY_ID` is optional and should normally be omitted (auto-derived).

## 5) Direct-Key Env Flow (alternative)

```bash
ICA_VC_SIGNING_PRIVATE_KEY_PEM=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
ICA_VC_SIGNING_ALG=ES384
ICA_VC_SIGNING_PREFERRED_ALG=ES384
```

## 6) Transition to CA-grade (production)

1. Generate controller + ICA CSRs with CLI.
2. Submit both to CA (same request/bucket package).
3. Receive CA chains.
4. Call `_activate` with canonical `body.data[]` entries (`privateKeyPem` + `x5c`/`certificateChainPem`).
5. Controller authorization must be in `body.signature.data` (detached compact JWS over canonical `body`).
6. Keep `DISABLE_CONTROLLER_DIDCOMM_PROOF=false` and `DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION=false`.

## 7) Canonical signature payload

Controller authorization canonicalization excludes:
- `body.signature`
- root `body.id` and `body.meta` only when `body.resourceType == "Bundle"`

It does not remove `text` or `contained`.
