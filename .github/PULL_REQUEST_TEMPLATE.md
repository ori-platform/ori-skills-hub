## What does this PR do?

<!-- Describe the change. Focus on WHY, not just what. -->

## Type of change

- [ ] `feat` - new Hub endpoint, storage, signing, validation, scanner, or admin workflow
- [ ] `fix` - bug fix or security/contract correction
- [ ] `docs` - documentation only
- [ ] `test` - tests only
- [ ] `refactor` - no behavior change
- [ ] `security` - touches signing, upload, tarball, author tokens, admin auth, or review gates
- [ ] `contract-change` - changes skill package, signing, or SDK/runtime-facing behavior

## Required checklist

- [ ] Linked issue is included below and acceptance criteria are addressed
- [ ] `pytest -q` passes
- [ ] `mypy hub tests` passes
- [ ] `ruff check hub tests` passes
- [ ] `ruff format --check hub tests` passes
- [ ] Pre-commit passes for changed files
- [ ] Every new `.py` file has the Apache-2.0 license header
- [ ] API docs or README are updated if endpoint behavior changed

## Hub trust and review checklist

- [ ] Upload/publish paths verify before storage
- [ ] Hub never imports or executes skill hook code
- [ ] Any skill declaring Tier C or Tier D action authority enters `pending_review`
- [ ] Tier C/D skills are not publicly listed or downloadable until admin approval
- [ ] Hub root Ed25519 signing uses `cryptography` and matches runtime canonical payload behavior
- [ ] Invalid signatures, tampered tarballs, malformed YAML, and traversal attempts have negative tests where applicable

## Admin, storage, and scanner checklist

Complete if this PR touches admin routes, persistence, local storage, tarballs, or scanner behavior.

- [ ] Admin endpoints require admin auth and author tokens cannot authorize admin actions
- [ ] Storage writes are path-safe and atomic
- [ ] Scanner failures fail closed into review/blocking behavior, not public listing
- [ ] Download counters and status transitions are tested for failure and boundary cases
- [ ] Secrets, private keys, admin keys, and tokens never appear in logs or errors

## If you used AI assistance

- [ ] I can explain every line of AI-generated code in this PR
- [ ] I have read and understood every file I modified
- [ ] I am not submitting code I cannot defend in review

## Related issue

<!-- Closes #<issue-number> -->

## Testing notes

<!-- Include commands run and any intentionally skipped checks. -->
