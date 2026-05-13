# Contributing

Contributions must preserve the Skills Hub security model.

Before opening a PR:

```bash
pre-commit run --all-files
pytest -q
```

Rules:

- Keep skill package semantics aligned with [`ori-specs`](https://github.com/ori-platform/ori-specs).
- Do not persist unsigned or unverified tarballs.
- Do not bypass the Tier C/D review gate.
- Do not add network calls to disabled optional integrations.
- Do not commit secrets or private signing keys.
