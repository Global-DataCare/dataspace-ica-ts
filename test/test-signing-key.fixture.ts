// EC P-384 test key for deterministic VC tests
// Private key (PEM)
export const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAiX/A2q1zlxi2BvEO1
83UVnc7vubVfmhhVJ+1zQTP+n55TmwRwv6StS1zsWjAJRBehZANiAATGgf+aHoGh
tFin6eQTtit8S1gYlzHpPPLT1fA5rUrwHdJxnGCV7X6J6UIRXrLWNN0EQGgfyxng
FPTBqnJ3Efl8sMQk8iV0KQu56KEQaBgBlt4J/zE2wZq7DWORHHktPV0=
-----END PRIVATE KEY-----`;

// Public JWK (correspondiente a la clave anterior)
export const PUBLIC_JWK = {
  kty: 'EC',
  crv: 'P-384',
  x: 'xoH_mh6BobRYp-nkE7YrfEtYGJcx6Tzy09XwOa1K8B3ScZxgle1-ielCEV6y1jTd',
  y: 'BEBoH8sZ4BT0wapydxH5fLDEJPIldCkLueihEGgYAZbeCf8xNsGauw1jkRx5LT1d',
};
