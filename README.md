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
- Async SQLAlchemy persistence with append-only transition audit.
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
  db/            async lifecycle, internal mappings, transactional repository
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

## Database

The current bootstrap uses SQLite through SQLAlchemy's async `aiosqlite` driver.
The existing `sqlite:///...` `HUB_DATABASE_URL` shorthand is normalized
internally. Other backends fail configuration explicitly until the deferred
PostgreSQL posture, driver, and equivalent database-level guards are delivered.

Apply schema changes with Alembic:

```bash
alembic upgrade head
```

`Database.bootstrap_schema()` exists for local and isolated test bootstrap and
is safe to call repeatedly. Deployed environments should use Alembic instead.
Writes go through `HubRepository`, which commits publication records and their
audit events atomically, performs conditional review transitions, and uses an
atomic database update for download counts. SQLite triggers also reject
physical mutation of artifacts or transition audit rows, forged audit
timestamps, illegal initial states, and illegal status transitions.

## Author Identity Bootstrap

Author registration is disabled by default. A deployment must opt in and
provide an explicit bootstrap authority:

```bash
HUB_ADMIN_API_KEY=<at-least-32-random-characters>
HUB_ADMIN_ACTOR_ID=bootstrap-admin
HUB_AUTHOR_REGISTRATION_ENABLED=true
HUB_AUTHOR_TOKEN_TTL_SECONDS=2592000
```

After applying migrations, start the environment-backed application factory:

```bash
alembic upgrade head
uvicorn hub.web.main:create_configured_app --factory
```

The registration, key-rotation, credential-rotation, and revocation endpoints
require the admin bearer credential plus `Idempotency-Key` and
`X-Correlation-ID` headers. Author bearer credentials cannot call these admin
endpoints. They identify a stable author actor for the publication API.

Author bearer credentials are generated from the operating system CSPRNG, not
derived from the admin key or another predictable value. The raw credential is
returned only during registration or credential rotation, with responses
marked `no-store`; the database retains only an opaque lookup value and a
SHA-256 digest. Key rotation, credential rotation, and revocation preserve
append-only identity history and invalidate superseded credentials
immediately.

An author bearer credential is reusable until it expires or is revoked. It is
not a per-request nonce, so deployments must expose these endpoints over HTTPS.
Identity mutation idempotency keys are single-use per authenticated admin
actor. Replaying one returns a conflict and never re-discloses a raw
credential.
Publication request idempotency and upload replay protection belong to the
publication pipeline rather than the identity bootstrap API.

The HUB-006 migration fails closed if it finds authors created through the
earlier unauthenticated database bootstrap. Those records cannot be promoted
into authenticated identities without inventing credential and audit history.
An operator must migrate or remove them explicitly before retrying the schema
upgrade. Downgrade also fails closed after an authenticated identity has been
registered, preventing silent deletion of key and audit history.

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

## Skill Archive Safety

Skill package inspection and rebuild use `hub.storage.tarball` and never extract
untrusted members onto the Hub filesystem. Accepted packages are gzip-compressed
tar archives containing exactly one `skill.yaml` at archive root or one
directory deep. Wrapped packages must keep every member under that one package
directory. Only canonical, portable regular-file and directory paths are
accepted; links, sparse files, devices, traversal, duplicate paths, ambiguous
manifests, YAML aliases, and non-JSON manifest values fail closed.

Default limits are 10 MiB compressed, 64 MiB expanded tar data, 512 members,
16 MiB per file, 48 MiB total file payload, and 512 KiB for `skill.yaml`.
Rebuilds preserve safe member paths and non-manifest payloads, normalize
untrusted archive metadata, and require every manifest field except the
top-level `signature` to remain semantically unchanged.

## Skill Contract Validation

Decoded manifests are validated by `hub.core.validation` without importing
runtime or SDK internals. The validator enforces the current skill-package v1
field shapes, trigger and action tiers, names, references, duplicate defenses,
history-placeholder limit, and Tier B/C/D execution invariants. Tier D is
rule-only even across action capability references, physical Tier B actions
require approval or post-action policy, and Tier C safe defaults must use the
built-in dashboard log or resolve to declared Tier A actions.

Review classification consumes the same validated result. Malformed metadata is
rejected instead of being classified for automatic listing, and any valid
trigger or declared action carrying Tier C/D authority requires manual review.
Descriptive top-level extensions remain intact and validation never opens or
executes package hook code.

## Security Gate

Any skill declaring Tier C or Tier D action authority must enter
`pending_review` and must not be publicly listed until admin approval.
