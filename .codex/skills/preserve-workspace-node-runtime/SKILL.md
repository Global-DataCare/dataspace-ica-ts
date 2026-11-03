---
name: preserve-workspace-node-runtime
description: Preserve the approved Node.js 26 workspace runtime for this ICA repository's installs, builds, tests, local services, E2E, releases and deployments.
---

# Preserve Workspace Node Runtime

This repository extends the canonical workspace
`preserve-workspace-node-runtime` contract. The approved global runtime is
Node.js `26.13.0`; repository ICA constraints remain authoritative here.

## Keep Node 26 active

1. Run `node --version` before the first install, build, test, service, E2E,
   Playwright, release or deployment command and record it with the evidence.
2. Use the workspace's active Node 26 runtime. The current approved runtime is
   Node `26.13.0`.
3. Keep the same Node executable and version for every retry and every process
   spawned by that gate.

## Never switch implicitly

- Never prepend another Node installation to `PATH`, run `nvm use`, use
  `npx node`, or otherwise select another Node version merely because
  `package.json#engines` lists a compatible range.
- Treat `engines` as compatibility metadata, not authorization to change the
  active workspace runtime.
- Do not add compatibility flags, modify `engines`, regenerate a lockfile or
  change dependencies to compensate for an unapproved runtime switch.

## Handle a genuine incompatibility

If a repository-owned, authoritative runtime pin rejects Node 26, or a command
fails specifically because Node 26 is unsupported:

1. Stop before changing the runtime or repository.
2. Report the active version, the repository pin and the exact failure.
3. Obtain explicit user authorization for any runtime change.
4. After authorization, apply the selected runtime consistently to the whole
   gate and record it in the resulting evidence.

A previous successful run under Node 24 is historical compatibility evidence,
not authorization to replace Node 26. Reproduce current gates under Node 26
first; do not manufacture a new failure by choosing another runtime.

## Synchronize the installed dependency tree

1. Treat the committed `package-lock.json` as authoritative and run `npm ci`
   before builds, tests, E2E, Playwright, release or deployment gates.
2. A clean Git worktree does not prove that `node_modules` matches the lock.
   An older installed internal package is operationally dirty even when
   `git status` is empty.
3. Record effective internal versions with `npm ls` after `npm ci`; never infer
   them only from `package.json` or the lockfile.

## Fail fast across browser and E2E matrices

Run the smallest failing journey and the first browser/project first. Configure
Playwright with `maxFailures: 1`, or stop the orchestration immediately after
the first failed project. Do not continue with mobile, sibling browsers or
later journeys after desktop has already failed. Correct the first failure,
rerun that focused project, and only then expand to the complete matrix. A
stopped sibling project is pending, never passing or skipped evidence.
