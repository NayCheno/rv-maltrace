# User Commit Rules

Follow the repository’s existing conventions first. Check files such as `CONTRIBUTING.md`, `README.md`, PR templates, package scripts, and recent commit history before committing.

Before every commit:

1. Inspect the working tree:

```bash
git status --short
git diff
git diff --stat
```

2. Stage only intentional changes related to the current task. Do not include unrelated edits, local config, logs, caches, build artifacts, debug files, secrets, or user changes.

3. Review the staged diff:

```bash
git diff --cached
git diff --cached --stat
```

4. Run relevant checks when available, such as tests, lint, formatting, typecheck, or project-specific validation commands. Do not claim checks passed unless they were actually run.

Commits must be atomic: one commit should represent one logical change. Do not create mixed, vague, or WIP commits.

Use the project’s commit message style. If none exists, use Conventional Commits:

```text
<type>(<scope>): <subject>
```

Examples:

```text
fix(parser): handle empty input
feat(api): add pagination support
docs(readme): clarify setup steps
test(auth): cover expired token flow
ci(github): cache dependencies
```

Common types:

```text
feat, fix, docs, test, refactor, perf, style, build, ci, chore, revert
```

Subject rules:

- use English unless the repo uses another language
- be specific and concise
- use imperative mood when possible
- do not end with a period
- avoid vague subjects like update, misc, changes, fix stuff, or wip

Add a body when the change needs context. Explain what changed, why, risks, migration notes, or testing. Keep it focused.

For breaking changes, use `!` and include a footer:

```text
feat(api)!: remove legacy token endpoint

BREAKING CHANGE: `/v1/token` has been removed. Use `/v1/session`.
```

Never commit secrets, credentials, tokens, real `.env` files, or private data. If a secret appears in the diff, stop and report it.

Do not use `--amend`, `--no-verify`, `--allow-empty`, reset, rebase, or forceful history-changing commands unless explicitly instructed.

After committing, report:

```text
Created commit <sha>: <subject>

Files changed:
- ...

Validation:
- <command>: passed/failed/not run with reason
```

A good commit should make it clear what changed, why it changed, and how it was validated.
