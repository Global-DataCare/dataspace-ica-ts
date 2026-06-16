# 01 Overview

## What this repository is

`dataspace-ica-ts` is the ICA service for:

- asynchronous onboarding and lifecycle APIs
- DID/JWKS/discovery publication
- signing key activation and credential issuance support
- CLI-based CA/bootstrap/publication operations

At a high level, the project combines:

- an API for business and trust flows
- a CLI for bootstrap and operator workflows
- supporting discovery artifacts and deployment assets

## Main capabilities

- `_verify`
  verifies signed Terms and Conditions PDF submissions
- `_activate`
  activates credential-signing key material
- `_add`
  ingests evidence records
- `_upsert`
  stores delegated or policy-like configuration
- `_issue`
  issues credentials
- `_status`
  queries lifecycle status
- `_revoke`
  applies revocation or terminal status changes

## Repository landmarks

- [`README.md`](../../README.md)
  entry guide and backward-compatible detailed reference
- [`src/api`](../../src/api)
  HTTP API implementation
- [`bin/ica-cli.js`](../../bin/ica-cli.js)
  CLI entrypoint
- [`test`](../../test)
  executable documentation and contracts
- [`docs/examples`](../examples)
  example fixtures and sample payload data
- [`deploy/k8s`](../../deploy/k8s)
  Kubernetes deployment assets

## How to read the docs

- Start with local startup and configuration.
- Then read the key endpoints and core flows.
- Then jump into tests and fixtures for concrete request/response examples.
- Use the architecture and deployment sections only when changing those areas.

## Scope boundary

This repo is not only a DID/JWKS publisher and not only a certificate tool.
It is the trust and onboarding service layer that sits between external callers,
operator workflows, and downstream trust material/publication concerns.

Current documentation boundary:

- ICA docs may describe the initial animal domain as `animal-pet-global`.
- ICA docs should not define the future veterinary taxonomy beyond that first domain.
- Detailed veterinary segmentation belongs in `uhc-sdk-core-ts`, not in this repo.
