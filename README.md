# ori-skills-hub

Community skill registry for the Ori platform.

The Skills Hub is the server-side distribution layer for community skills. It is
not the trust boundary by itself: the Hub verifies signatures at publish time,
and [`ori-runtime`](https://github.com/ori-platform/ori-runtime) verifies
signatures again before loading community skills.

## Scope

Bootstrap scope:

- FastAPI-oriented service boundary.
- Skill metadata and review status models.
- Ed25519 signature format parsing and `cryptography`-backed verification wrapper.
- Tier C/D review gate helpers.
- Local filesystem storage backend for signed tarballs.
- Optional VirusTotal scan wrapper with safe disabled behavior.
- CI, pre-commit, license headers, and contribution guardrails.

Deferred production scope:

- Hub root keypair generation, hub re-signing, and full publish pipeline.
- PostgreSQL backend.
- S3-compatible tarball storage.
- GitHub OAuth author registration.
- Full publish/download API persistence.
- Runtime SkillLoader integration matrix against released runtime versions.

## Contract Baselines

| Component | Baseline |
|---|---|
| Runtime | [`ori-runtime`](https://github.com/ori-platform/ori-runtime) `v0.9.0-beta.2+` |
| Specs | [`ori-specs`](https://github.com/ori-platform/ori-specs) `v1` |

Relevant contracts:

- [`skills-package/v1`](https://github.com/ori-platform/ori-specs/blob/main/skills-package/v1.md)
- [`signing/v1`](https://github.com/ori-platform/ori-specs/blob/main/signing/v1.md)

## Package Layout

```text
hub/
  core/          config, models, review gate, validation contracts
  security/      Ed25519 signature verification
  storage/       local storage backend now; S3 later
  integrations/  optional external scanners/services
  web/           FastAPI app assembly
```

## Dependency Policy

Human-edited dependency intent lives in `requirements.in` and
`requirements-dev.in`, and `pyproject.toml` must mirror those ranges exactly.
Pinned install artifacts live in `requirements.txt` and `requirements-dev.txt`.
This mirrors [`ori-runtime`](https://github.com/ori-platform/ori-runtime) and
keeps bootstrap installs reproducible while still making dependency updates
reviewable.

When changing dependencies, edit the `.in` file first, mirror that intent in
`pyproject.toml`, regenerate the matching `.txt` file with `pip-compile`, and
review the diff before committing. `scripts/check_dependency_alignment.py` keeps
these files from drifting.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install --no-deps -e .
pre-commit install
pre-commit run --all-files
pytest -q
```

## Security Gate

Any skill declaring Tier C or Tier D action authority must enter
`pending_review` and must not be publicly listed until admin approval.
