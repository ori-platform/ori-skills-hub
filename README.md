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
- Profile-separated Ed25519 signing, verification, and Hub key management.
- Tier C/D review gate helpers.
- Local filesystem storage backend for signed tarballs.
- Optional VirusTotal scan wrapper with safe disabled behavior.
- CI, pre-commit, license headers, and contribution guardrails.

Deferred production scope:

- Full authenticated publish pipeline and atomic Hub re-signing workflow.
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
  security/      profile-separated Ed25519 signing and key management
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

## Hub Signing Keys

The Hub uses distinct APIs for the two signing profiles in
`ori-specs/signing/v1`:

- the manifest profile signs the canonical parsed `skill.yaml` mapping for
  runtime verification;
- the artifact profile signs the exact final downloadable bytes and emits
  strict detached metadata for SDK/CLI verification.

Generate isolated profile keys into a new directory outside every Git
worktree:

```bash
ori-hub-keys generate --output-dir /secure/bootstrap/ori-hub-keys
```

The command creates private files with mode `0600`, refuses to overwrite an
existing directory, and prints only file locations and public trust anchors.
It does not print private key material. Separate profile keys are the default;
`--shared-root-key` must be supplied explicitly to use one keypair for both
profiles.

Production secret configuration must use exactly one of these forms:

```text
HUB_ROOT_SIGNING_PRIVATE_KEY_FILE=/run/secrets/hub-root-private-key.b64
```

or:

```text
HUB_MANIFEST_SIGNING_PRIVATE_KEY_FILE=/run/secrets/hub-manifest-private-key.b64
HUB_ARTIFACT_SIGNING_PRIVATE_KEY_FILE=/run/secrets/hub-artifact-private-key.b64
```

The corresponding `*_B64` variables are supported for secret managers that
inject environment values directly. File and inline sources cannot be mixed
for the same key, and shared-root material cannot be combined with
profile-specific material. Publish-capable startup fails closed when sources
are missing, partial, malformed, or ambiguous. Read-only mode may omit them.

Only `manifest_public_key_b64` and `artifact_public_key_b64` are exposed by the
safe trust-anchor and health surfaces. The shared signing vector corpus is
pinned at SHA-256
`13832babac98468ddd368aafd04c5140bba771f568500c50d4bac60c8588fddc`.

## Security Gate

Any skill declaring Tier C or Tier D action authority must enter
`pending_review` and must not be publicly listed until admin approval.
