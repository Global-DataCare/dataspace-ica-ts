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

