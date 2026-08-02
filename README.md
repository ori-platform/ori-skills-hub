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

`GET /health` reports the Hub release version and its supported skill-package
and signing contract compatibility. Signing compatibility includes the artifact
metadata schema and pinned signing-vector SHA-256; it never reports a runtime
release number, secrets, or raw deployment configuration.

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

## Publish API

Authenticated authors publish a signed skill archive with `POST /api/skills`.
The request body is the raw gzip-compressed tarball. It requires these headers:

- `Authorization: Bearer <author credential>`
- `X-Author-Artifact-Metadata`: strict JSON detached metadata for the author's
  signature over the exact upload bytes
- `Idempotency-Key`: a single-use publication request key
- `X-Correlation-ID`: an operator-visible request correlation identifier

The Hub verifies the author signature before archive inspection or durable
storage. A successful request returns `201 Created` with `name`, `version`,
`status`, `artifact_digest`, and `manifest_digest`; it never returns signature
material. Replayed idempotency keys and existing skill versions return `409`.
Malformed, invalid, or tampered archives and metadata return `422`; archives
over the ingress limit return `413`.

Tier C/D skills always enter `pending_review`. A suspicious or unavailable
scanner result also remains `pending_review`, even for lower-tier skills. Hub
admission is distribution evidence, not runtime authority: `ori-runtime`
independently verifies the signed package before execution.

## Admin Review API

Review endpoints require the configured admin bearer credential plus a
single-use `Idempotency-Key` and an operator-visible `X-Correlation-ID`.
Every transition also requires a non-empty JSON `reason`; the authenticated
admin actor, prior and new state, reason, correlation ID, and idempotency key
are recorded in append-only audit history.

- `GET /api/admin/skills` lists pending-review records; use `limit` (1-100) to
  bound the result set.
- `POST /api/admin/skills/{name}/{version}/approve` transitions a
  `pending_review` skill to `listed`.
- `POST /api/admin/skills/{name}/{version}/reject` transitions a
  `pending_review` skill to `rejected`.
- `POST /api/admin/skills/{name}/{version}/unlist` transitions a `listed`
  skill to `unlisted` without deleting its artifact or audit history.

Invalid, stale, concurrent, or replayed transitions return `409`; missing
skills return `404`. Author bearer credentials are never accepted by these
endpoints.

## Public Skill API

Public endpoints expose only listed skill versions. Pending-review, rejected,
and unlisted records return `404` and are never included in public results.

- `GET /api/skills` returns up to 100 public version summaries; use `limit`
  (1-100) to bound the result set.
- `GET /api/skills/{name}` returns every listed version for that name.
- `GET /api/skills/{name}/download?version={version}` returns the exact signed
  gzip tarball for one listed version. `version` is required; the Hub never
  selects an implicit latest version.

Downloads use `application/gzip` with a safe attachment filename. The Hub
returns `X-Hub-Artifact-Metadata`, a bounded strict JSON document containing
the v1 schema, artifact digest, and Hub detached signature for the exact
response bytes. Consumers must verify this metadata against the Hub artifact
trust anchor before extracting the archive. The Hub verifies the stored
content-addressed object before incrementing its download counter; unavailable
or corrupted artifacts return `503` without incrementing the counter.

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

Set `HUB_PUBLISH_ENABLED=true` to mount the publish, public skill, and admin
review routes. This mode also requires `HUB_VIRUSTOTAL_API_KEY`; startup fails
closed if either the scanner key or a complete signing-key configuration is
absent. Leave it unset or `false` for explicit read-only operation.

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

## Malware Scanning

VirusTotal scanning is optional for local development. Setting
`HUB_VIRUSTOTAL_API_KEY` enables submission of the author-supplied skill archive
to the fixed VirusTotal v3 [file upload endpoint](https://docs.virustotal.com/reference/files-scan),
followed by bounded polling of the returned
[analysis](https://docs.virustotal.com/reference/analysis). VirusTotal's
standard file API may share submitted samples with its security community, so
deployments must account for that external data handling before enabling the
integration. Production operators must also use an API entitlement that permits
their commercial workflow and comply with the applicable
[VirusTotal API terms](https://docs.virustotal.com/reference/getting-started);
a community/public API key is not sufficient authorization for commercial Hub
operation.

Production publication uses durable asynchronous orchestration. After author
authentication, exact-byte signature verification, bounded validation, Hub
signing, and immutable storage, the Hub atomically creates a non-public
publication and a `pending_submission` scan job. The HTTP request returns
`202 Accepted`; a background worker later submits the verified author archive
and polls one analysis response per leased attempt. Publish requests never wait
for VirusTotal queueing or polling.

Jobs use atomic, expiring worker leases, bounded exponential backoff with
jitter, bounded `Retry-After`, an attempt budget, and a maximum lifetime. Every
state and evidence change is recorded. Expired leases are recoverable after a
worker or service restart. Shutdown cancels the local worker without deleting
jobs or leases; any active lease expires and another worker can recover it.
Provider submission is at-least-once when termination happens after VirusTotal
accepts a sample but before its opaque analysis ID commits. Duplicate provider
submission cannot duplicate the Hub publication, scan job, evidence-driven
visibility transition, or audit record.

The exact verified author upload is retained in content-addressed local storage
as durable scanner input and evidence, including when the eventual verdict is
malicious. It is never served by public download routes. Operators must include
this non-public evidence store in their retention and deletion policy; automated
retention cleanup is not yet implemented.

A result is
`clean` only when VirusTotal reports a completed analysis, zero malicious and
suspicious detections, and a strict majority of affirmative `harmless` results
over all `undetected`, failed, timed-out, confirmed-timeout, and unsupported
engine outcomes. An all-`undetected` result, a tie, or an inconclusive majority
requires manual review. Malicious detections return `malicious`; suspicious,
inconclusive, malformed, timed-out, rate-limited, authentication-failed, and
other unavailable outcomes remain non-public for retry or manual review.

Clean Tier A/B publications are listed only after the normalized evidence is
durable and the existing append-only audit transition commits in the same
transaction. Clean Tier C/D publications remain pending manual review.
Malicious publications are rejected through the same audited transition path.
Exhausted, suspicious, malformed, rate-limited, authentication-failed, and
unavailable jobs never list automatically.

Without an API key the scanner records `skipped`. Under the Hub listing policy,
both `skipped` and `pending_manual_review` keep an upload pending for a human
decision; scanner unavailability never produces an automatic listing. API keys
are sent only in the VirusTotal `x-apikey` request header and are not included in
scanner results or logs.

Authenticated authors can query the bounded, non-secret scan status URL returned
by publication. Administrators can inspect `/api/admin/skills/scan-metrics` for
queue depth, oldest age, attempts, verdict counts, rate limits, exhausted jobs,
and worker latency. Provider analysis identifiers, raw provider responses,
author credentials, API keys, and private signing material are not exposed.

## Security Gate

Any skill declaring Tier C or Tier D action authority must enter
`pending_review` and must not be publicly listed until admin approval.
