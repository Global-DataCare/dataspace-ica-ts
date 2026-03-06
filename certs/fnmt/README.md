# FNMT trust material

Place the FNMT trust chain used by `_verify` in this folder:

- `fnmt-root.pem`: FNMT root CA certificate in PEM format.
- `fnmt-intermediate.pem`: FNMT intermediate CA certificate in PEM format.

The API reads these files by default from:

- `certs/fnmt/fnmt-root.pem`
- `certs/fnmt/fnmt-intermediate.pem`

You can override both paths with env vars:

- `ICA_FNMT_ROOT_CERT_PATH`
- `ICA_FNMT_INTERMEDIATE_CERT_PATH`

Alternative trust material sources:

- Inline PEM env vars:
  - `ICA_FNMT_ROOT_CERT_PEM`
  - `ICA_FNMT_INTERMEDIATE_CERT_PEM`
- Optional auto-download on startup:
  - `ICA_FNMT_AUTO_DOWNLOAD=true`
  - `ICA_FNMT_ROOT_CERT_URL` (optional; default official FNMT root URL if omitted)
  - `ICA_FNMT_INTERMEDIATE_CERT_URLS` (optional CSV)
  - `ICA_FNMT_INTERMEDIATE_CERT_URL` (legacy single URL)
  - Optional pins:
    - `ICA_FNMT_ROOT_CERT_PIN_SHA256`
    - `ICA_FNMT_INTERMEDIATE_CERT_PINS_SHA256` (CSV)
    - `ICA_FNMT_INTERMEDIATE_CERT_PIN_SHA256` (legacy single pin)
    - `ICA_FNMT_ROOT_CERT_PIN_SHA1`
    - `ICA_FNMT_INTERMEDIATE_CERT_PINS_SHA1` (CSV)
    - `ICA_FNMT_INTERMEDIATE_CERT_PIN_SHA1` (legacy single pin)
