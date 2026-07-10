# Repository Guidelines

## Project Overview
NoteTweet is an Obsidian community plugin for posting tweets and threads to X
(formerly Twitter) directly from your notes. It provides a writing-first composer
modal, "post selection" and "post file as thread" commands, `THREAD START` /
`THREAD END` parsing, auto-splitting at the 280-character limit, image
attachments, an optional post-tweet tag, delete/undo of just-posted tweets, and
an optional self-hosted scheduler. API credentials live in Obsidian's built-in
encrypted Secret Storage, not in `data.json`.

## Project Structure & Module Organization
Source lives in `src/`. Plugin registration and command wiring are in
`src/main.ts`; the X API client is `src/xApi.ts` (with OAuth 1.0a signing in
`src/oauth1.ts`); tweet parsing/splitting is `src/tweet.ts`; settings and their
`DEFAULT_SETTINGS` are `src/settings.ts` and `src/settingsTab.ts`; credential
storage is `src/secrets.ts` (with `src/legacyCrypt.ts` for migrating older
encrypted vaults); the scheduler client is `src/scheduler.ts`; modal UI is under
`src/Modals/`; user-facing logging is `src/log.ts`.

Tests are co-located with their source (`src/**/*.test.ts`). The drift test for
the E2E runner config is `tests/e2e-config.test.ts`. The Vitest runtime alias for
`import ... from "obsidian"` is `tests/obsidian.ts` (a re-export of the shared
`obsidian-test-kit` stub). The live Obsidian E2E suite is under `tests/e2e/`.

Generated artifacts: `main.js` is git-ignored and built into the repo root for
release packaging, not hand-edited. `styles.css` is a hand-written, committed
release asset.

## Tooling & GitHub
- Use `pnpm` for package management and scripts. Avoid npm/yarn/bun. Node 22 and
  the pnpm version are pinned in `.mise.toml`.
- Use the GitHub CLI (`gh`) for issues, PRs, and releases.
- When resolving a GitHub issue, use `gh issue develop <issue-number>` to
  create/link the working branch before implementation.
- Follow Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`,
  `release(version): ...`) so semantic-release can determine versions. PRs are
  squash-merged and the PR title becomes the squash commit that drives the
  released version; the `PR Title` CI check enforces this.
- GitHub does not allow approving your own PR from the same account; do not block
  merge waiting for self-approval.

## Build, Test, and Development Commands
- `pnpm run dev`: watch-mode esbuild build, regenerating `main.js` as you edit.
- `pnpm run build`: typecheck, then production esbuild bundle (`main.js`).
- `pnpm run lint`: ESLint over the TypeScript sources.
- `pnpm run typecheck`: `tsc --noEmit` over `src/`.
- `pnpm run test`: Vitest unit suite (jsdom-free, `node` environment).
- `pnpm run test:coverage`: unit suite with V8 coverage.
- `pnpm run test:e2e`: build, e2e typecheck, then run the live Obsidian E2E suite
  (`tests/e2e/`).
- `pnpm run obsidian:e2e -- <command>`: run an `obsidian` CLI command against an
  isolated, auto-provisioned worktree instance (see below).

Before opening a PR, run the CI-equivalent checks locally:

```bash
pnpm run lint
pnpm run build
pnpm run test
pnpm run typecheck:e2e
```

## Coding Style & Naming Conventions
Tab indentation is used in config; source follows the existing 2-space TypeScript
style. Use camelCase for variables and functions, PascalCase for classes and
modal components. Prefer inline type-only imports (ESLint enforces
`consistent-type-imports`). Route user-facing messages through `src/log.ts`
(NoteTweet surfaces everything as Obsidian notices, not console logs).

## Testing Guidelines
Vitest runs in the `node` environment and aliases `obsidian` to
`tests/obsidian.ts`, which re-exports the shared, node-safe `obsidian-test-kit`
stub; it cannot load real Obsidian modules. If a test needs an Obsidian API the
kit does not cover, add it to `obsidian-test-kit` rather than forking a local
stub. Structure production code so Obsidian dependencies sit behind seams; unit
tests target pure logic (tweet splitting, OAuth signing, secrets migration,
datetime helpers) and mock `obsidian` where they exercise the X client. Add
regression coverage for every bug fix, and ensure `pnpm run test` passes before
pushing.

When a bug depends on real Obsidian runtime behavior - the composer modal,
command registration, Secret Storage, image upload, or settings migration -
reproduce it in Obsidian before changing code and verify it there after the fix.
Record the exact Obsidian version, platform, vault setup, command or API call
invoked, console/runtime errors, and plugin state before and after.

## Obsidian Runtime Workflow (isolated worktree instance)
In a worktree, do **not** race a shared `dev` vault - multiple worktree agents
would clobber each other on the plugin symlink, `data.json`, and
`plugin:reload`. Use the shared `obsidian-e2e` instance runner instead. The four
`provision:e2e-vault` / `start:e2e-obsidian` / `stop:e2e-obsidian` /
`obsidian:e2e` scripts run on the `obsidian-e2e` bin, configured by
`obsidian-e2e.config.mjs` at the repo root (plugin id `notetweet`, the three
symlinked artifacts `manifest.json` / `main.js` / `styles.css`, and the
`DEFAULT_SETTINGS`-shaped `data.json` seed). The runner provisions a
worktree-local vault, starts or reuses a private-`HOME` Obsidian instance bound
to it, disables Restricted Mode, waits until NoteTweet is live
(`Boolean(app.plugins.plugins["notetweet"])`), then runs your command:

```bash
pnpm run build                                 # produce root main.js + manifest.json + styles.css first
pnpm run obsidian:e2e -- eval code='app.vault.getName()'
pnpm run obsidian:e2e -- eval code='Boolean(app.plugins.plugins.notetweet)'
pnpm run obsidian:e2e -- dev:errors
```

- The runner links the worktree's own `main.js` / `manifest.json` / `styles.css`
  and seeds a clean `DEFAULT_SETTINGS`-shaped `data.json` on first provision.
- `pnpm run provision:e2e-vault` and `pnpm run start:e2e-obsidian` expose the
  provision/launch steps individually; both accept `--help`.
- To point the Vitest `tests/e2e` suite at the isolated instance, the `obsidian`
  CLI routes by `$HOME` (it talks to `$HOME/.obsidian-cli.sock`), so you must
  remap `HOME` as well as the vault name. `--print-env` emits the canonical
  `OBSIDIAN_E2E_*` names (the runner also emits legacy `NOTETWEET_E2E_*` aliases
  during the migration; the harness reads canonical first, then the alias):

  ```bash
  pnpm run build                                 # provisioning links main.js
  eval "$(pnpm run --silent start:e2e-obsidian -- --print-env)"
  export HOME="$OBSIDIAN_E2E_OBSIDIAN_HOME"      # re-point the CLI socket
  pnpm run test:e2e
  ```

### Stopping an isolated instance (avoid leaks)
Each started instance is a real Obsidian process tree plus a private profile
directory. Removing a worktree does **not** stop it. Stop it explicitly:

```bash
pnpm run stop:e2e-obsidian                # stop THIS worktree's instance + remove its tmp dir
pnpm run stop:e2e-obsidian -- --dry-run   # show what would be stopped/removed
pnpm run stop:e2e-obsidian -- --prune     # also reap orphaned instances (worktree gone)
```

The teardown targets only this worktree's instance; the shared `dev` vault, other
worktrees, and other plugins' instances are untouched. `start:e2e-obsidian` and
`obsidian:e2e` also reap any orphaned instance (whose backing worktree no longer
exists) before launching, so you rarely need `stop` by hand.

## Evidence-First Bug Triage
- Default workflow: reproduce in Obsidian first, then implement the fix, then
  verify in Obsidian again, then add/adjust unit tests for regression coverage.
- Do not assume a reported bug still exists; confirm current behavior before
  changing code. Issues may already be fixed by unrelated changes (NoteTweet was
  substantially rewritten in July 2026).
- Prefer real user conditions over synthetic tests (composer modal, selection vs
  file-thread commands, settings state, credential storage, platform specifics -
  image upload is desktop only).

## Release & PR Expectations
Releases are semantic-release based and cut manually via the Release workflow
(Actions tab or `gh workflow run release.yml`); pushes to `master` do not
auto-release. `version-bump.mjs` keeps `manifest.json` and `versions.json` in
sync with the package version and Obsidian `minAppVersion`. Release assets are
`main.js`, `manifest.json`, and `styles.css`, and each release is attested with
build provenance. Treat unexpected diffs in `package.json`, `pnpm-lock.yaml`,
`manifest.json`, or `versions.json` as blockers until understood.

Pull requests should include: a concise summary of the user-facing change; linked
issues when relevant; screenshots or recordings for visible UI changes; the exact
commands run and whether Obsidian runtime verification was performed; and
release/migration impact (especially for settings, secret storage, or X API
changes). Keep changes scoped - do not mix unrelated formatting, dependency
churn, or generated-artifact changes into a feature or bug-fix commit.
