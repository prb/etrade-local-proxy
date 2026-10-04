---
inclusion: always
---

# Git Workflow

Apply these rules for all version-control work in this project. The default branch is
`main`; if a repo you're working against uses a different default (e.g. `master`),
adapt the branch names accordingly.

- **Branch before building.** Start non-trivial work on a feature branch off an up-to-date `main`, never commit directly to `main`. Name branches `feature/<short-description>`, `fix/<short-description>`, or `chore/<short-description>` for non-code changes.
- **Confirm before committing.** Only create commits when explicitly asked. If it is unclear whether to commit, ask first.
- **Stage deliberately.** Add specific files by name. Avoid `git add -A` / `git add .` so unrelated in-progress work is not swept into a commit.
- **Don't commit secrets.** Never stage `.env` files, credentials, keys, or tokens. Flag them if you notice them staged or in the working tree.
- **Keep commits scoped.** One logical change per commit. Do not commit unrelated changes that happen to be present in the working tree.
- **Write clear messages.** Use a concise imperative subject under ~70 characters; use the body to explain the *why* when it is not obvious.
- **Prefer new commits over rewriting history.** Avoid `--amend`, `rebase`, force-push, `reset --hard`, and `clean -f` unless explicitly requested.
- **Preserve hooks.** Do not skip hooks (`--no-verify`) unless explicitly asked.
- **Push to a new branch, open a PR.** Push feature branches with upstream tracking and open a pull request for review rather than merging to `main` directly.
