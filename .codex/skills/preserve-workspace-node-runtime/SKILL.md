---
name: preserve-workspace-node-runtime
description: Preserve the active Node.js 24 workspace runtime for installs, builds, tests, local services, E2E, Playwright, releases and deployments. Use before running any Node or npm command, interpreting package.json engines, selecting a Node executable, or diagnosing a runtime-version failure in any workspace repository.
---

# Preserve Workspace Node Runtime

## Keep Node 24 active

1. Run `node --version` before the first install, build, test, service, E2E,
   Playwright, release or deployment command and record it with the evidence.
2. Use the workspace's active Node 24 runtime. The current approved runtime is
   Node `24.15.0`.
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

If a repository-owned, authoritative runtime pin rejects Node 24, or a command
fails specifically because Node 24 is unsupported:

1. Stop before changing the runtime or repository.
2. Report the active version, the repository pin and the exact failure.
3. Obtain explicit user authorization for any runtime change.
4. After authorization, apply the selected runtime consistently to the whole
   gate and record it in the resulting evidence.

A previous successful run under Node 24 is evidence to reproduce that same
environment first; do not manufacture a new failure by choosing another
runtime.

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
