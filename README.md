# etz

`etz` is a CLI for managing multi-repo workspaces where the parent folder is **not** a git repo and each direct child folder is an independent git repo.

It creates coordinated git worktrees under:

- `parent/.etz/workspaces/<workspace>/<repo>`

## Commands

- `etz init`
- `etz add <workspace> --branch <branch> [--no-copy-root]`
- `etz list`
- `etz refresh [--check] [--json]`
- `etz status [workspace] [--changed] [--summary] [--json]`
- `etz commit [workspace] -m "msg" [--all] [--dry-run] [--json]`
- `etz push [workspace] [--dry-run] [--json]`
- `etz remove <workspace> [--force]`
- `etz prune`
- `etz doctor [--fix] [--json]`

## Behavior Highlights

- Repo discovery is **direct children only**.
- Missing branch on `add` is auto-created from each repo's detected default branch.
- `refresh` re-discovers direct-child repos and updates the manifest lock file.
- `refresh --check` reports drift and exits non-zero without mutating files.
- `add` copies non-repo files/directories from the parent root into the workspace root by default.
- Use `--no-copy-root` to disable that copy behavior.
- Optional `.etzcopy` and `.etzignore` patterns let you include/exclude root files copied into a workspace.
- `add` and `remove` are fail-fast and attempt rollback on partial failures.
- If you run `etz` from inside `.etz/workspaces/<workspace>/...`, `status`, `commit`, and `push` infer the workspace automatically.
- `status` includes per-repo staged/unstaged/untracked counts.
- `status --changed` filters to changed repos; `status --summary` prints condensed totals.
- `commit` works across repos in one workspace:
  - default: commits only repos with staged changes
  - smart fallback: if nothing is staged but tracked files changed, it auto-stages tracked changes (`git add -u`) and commits
  - `--all`: stages all tracked + untracked changes (`git add -A`) first
  - `--dry-run`: shows what would be committed and what would be auto-staged, without changing any repo
  - on failure in later repos, previously created commits from this run are rolled back with `git reset --soft HEAD~1`
- `push` pushes repos that are ahead of upstream; `--dry-run` previews push candidates.
- `doctor --fix` can prune stale workspace state entries and attempt branch realignment where safe.
- State is persisted in:
  - `.etz/config.toml`
  - `.etz/manifest.lock.toml`
  - `.etz/state.toml`

## Installation

See `INSTALLATION.md` for all install options (Cargo, Homebrew, binaries, source build).

## Quick Start

```bash
# inside parent folder that contains git child repos
etz init
etz add feat-auth --branch feat-auth
etz status feat-auth

# after making/staging changes
etz commit feat-auth -m "feat: implement auth flow"

# cleanup
etz remove feat-auth
```
