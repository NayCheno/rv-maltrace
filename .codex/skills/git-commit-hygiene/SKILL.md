---
name: git-commit-hygiene
description: Create clean, scoped, validated Git commits. Use when Codex is asked to commit, stage, split changes into commits, write commit messages, inspect staged changes, prepare commit summaries, or decide what belongs in a commit in this repository or another Git worktree.
---

# Git Commit Hygiene

Use this skill to create commits that are reviewable, reproducible, and respectful of user changes. The goal is not merely to run `git commit`; the goal is to make one logical patch with a clear message and a defensible validation record.

Follow `references/user-commit-rules.md` as the authoritative checklist for commit mechanics and reporting. Repository conventions still come first when choosing message style.

## Commit Workflow

### 1. Establish Scope

Inspect before staging:

```powershell
git status --short
git diff
git diff --stat
git log -5 --pretty=format:"%h %s"
```

Also check convention sources when present:

- `CONTRIBUTING.md`
- `README.md`
- `.github/PULL_REQUEST_TEMPLATE*`
- package scripts or project task docs
- recent commit history

Classify files into:

- intended changes for the current request
- unrelated user changes
- generated artifacts that should be excluded
- secrets or private data that require stopping

Do not stage unrelated user changes. Do not revert unrelated changes.

### 2. Choose Commit Granularity

Make one commit per logical change. Split commits when changes answer different review questions, for example:

- docs-only plan update
- RTL behavior change
- parser/golden update
- board evidence update
- formatting-only cleanup

Keep generated files with the source change only when the project expects them to be versioned.

### 3. Validate Before Commit

Run the narrowest meaningful validation for the touched surface.

For this repository, prefer:

```powershell
uv run rvmt config:show
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run rvmt sim:summary
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_<area>.py
```

For docs-only changes, run the matching `tools/check_*.py` gate when it exists. If no check exists, at least inspect rendered structure and run `git diff --check` or `git diff --cached --check`.

If validation cannot run, say why in the final response. Never claim a check passed unless it ran.

### 4. Stage Intentionally

Stage only the intended paths:

```powershell
git add -- <path1> <path2>
git diff --cached
git diff --cached --stat
git diff --cached --check
```

For partial staging, use non-interactive path-specific staging when possible. Be cautious with interactive patch mode in automated contexts.

Stop before committing if staged diff includes:

- credentials, tokens, private keys, `.env` secrets
- unrelated files
- build products not intended for version control
- accidental large vendor/generated churn

### 5. Write the Message

Follow existing repository history first. If no local convention exists, use Conventional Commits.

This repository currently uses short imperative subjects such as:

```text
Add next-stage research plan
Add semantic enrichment strategy gate
Add board trace validation programs
```

Use this shape unless the repository adopts Conventional Commits:

```text
Add <specific artifact or behavior>
Update <specific gate or workflow>
Fix <specific bug or mismatch>
Document <specific decision or evidence>
```

If the repository has no discernible style, use Conventional Commits:

```text
<type>(<scope>): <subject>
```

Common types:

```text
feat, fix, docs, test, refactor, perf, style, build, ci, chore, revert
```

For breaking changes, use `!` and add a `BREAKING CHANGE:` footer.

For larger or risky changes, add a body with:

- what changed
- why it changed
- validation run
- known limitations or follow-up gates

Avoid vague subjects:

```text
update
misc
fix stuff
wip
changes
```

### 6. Commit and Confirm

Commit:

```powershell
git commit -m "<subject>"
```

Then confirm:

```powershell
git status --short
git show -s --format="%H%n%an <%ae>%n%s" HEAD
```

Report:

- commit SHA and subject
- files changed
- validation commands and outcomes
- any checks not run with reason

Use this report shape:

```text
Created commit <sha>: <subject>

Files changed:
- ...

Validation:
- <command>: passed/failed/not run with reason
```

## Message Style Decision

Use this order:

1. Existing repository style from recent `git log`.
2. Project contributing docs, if present.
3. Conventional Commits only when the repository already uses it or the user requests it.
4. Plain imperative subject otherwise.

Use `references/commit-patterns.md` when deciding between imperative, Conventional Commit, subsystem-tagged, or body-heavy messages.

## Safety Rules

- Never use `git reset --hard`, `git checkout --`, rebase, amend, or force push unless explicitly requested.
- Do not use `--amend`, `--no-verify`, `--allow-empty`, reset, rebase, or forceful history-changing commands unless explicitly instructed.
- Never include untracked directories wholesale without inspecting them.
- Never commit private keys or credentials. If a secret appears in the diff, stop and report it.
- Do not rely on author identity assumptions; check `git config --local --get-regexp "^user\\."` when identity matters.
- If the user asks to push after committing, verify remote/branch state and use the repository’s configured SSH identity.
