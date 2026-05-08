# Commit Patterns Distilled from Mature Projects

## Common Principles

Mature open-source projects differ in exact message style, but converge on these practices:

- one logical change per commit
- inspect worktree and staged diff before committing
- keep subject specific and reviewable
- include rationale in the body when the change is non-obvious
- run project-specific checks before submission
- do not mix generated churn, formatting, and semantic changes without a reason
- preserve contributor/user changes that are outside the current task

## Style Families

### Repository-local imperative style

Use when recent history uses plain imperative subjects.

```text
Add trace export decision gate
Fix syscall return comparison
Document board validation evidence
```

Best for small repositories with human-read history and no automated changelog requirement.

### Conventional Commits

Use when the repository already follows it or the user requests machine-readable commit types.

```text
feat(trace): add syscall return packet
fix(parser): handle missing tval values
docs(board): clarify Genesys 2 evidence gate
test(trace): cover FIFO drop events
```

Common types:

```text
feat, fix, docs, test, refactor, perf, style, build, ci, chore, revert
```

For breaking changes:

```text
feat(trace)!: change compact packet header

BREAKING CHANGE: compact trace readers must consume payload_len from the header.
```

### Subsystem-tagged subjects

Use when a large hardware project convention tags areas in the subject.

```text
[trace/rtl] Add syscall return matching
[docs/board] Record baseline pass criteria
[tools] Tighten golden trace comparison
```

This is useful when a project has many subsystems and reviewers scan logs by area.

### Body-heavy rationale commits

Use for riskier changes, bug fixes, or behavior changes where reviewers need context.

```text
Fix ECALL capture on trap path

ECALL does not always satisfy the normal retire predicate because it raises an
exception. Capture it from the committed trap path so syscall entry events are
not dropped.

Validation:
- uv run rvmt sim:trace-unit
```

## RV-MalTrace Defaults

Current history uses short imperative subjects without prefixes. Prefer:

```text
Add <artifact>
Update <workflow>
Fix <behavior>
Document <decision>
Tighten <check>
```

Use a body when the commit changes trace semantics, validation gates, board claims, or expected/golden outputs.

## Pre-Commit Checklist

```text
[ ] git status --short reviewed
[ ] git diff reviewed
[ ] unrelated user changes excluded
[ ] secrets absent
[ ] generated files intentional
[ ] relevant validation run or reason recorded
[ ] staged diff reviewed
[ ] subject matches repository style
```

## Source Practices Reflected

- Git documentation emphasizes inspecting repository state and staged content with status/diff before committing.
- Linux kernel patch guidance emphasizes clear problem statements, rationale, and checking patches before submission.
- OpenTitan contribution guidance uses subsystem-aware subjects for scoped changes in a large hardware repository.
- Conventional Commits provides a machine-readable format when a project needs typed changelogs or release automation.
