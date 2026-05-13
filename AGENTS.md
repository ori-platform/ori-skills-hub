# AGENTS.md - ori-skills-hub

This repository implements the community skill registry for Ori.

## Purpose

`ori-skills-hub` exists to publish, discover, verify, review, and distribute
community skills. It complements [`ori-runtime`](https://github.com/ori-platform/ori-runtime):
Hub verifies at upload time, runtime verifies again at install/load time.

## Invariants

1. `HUB-1` Verify before storage.
Unsigned or tampered skill tarballs must be rejected before they are persisted.

2. `HUB-2` Runtime remains the final trust boundary.
The Hub never weakens [`ori-runtime`](https://github.com/ori-platform/ori-runtime)
community skill verification. Hub acceptance is not runtime trust.

3. `HUB-3` Tier C/D review gate is mandatory.
Skills declaring Tier C or Tier D action authority are set to `pending_review`
and are not listed until admin approval.

4. `HUB-4` Contracts come from specs.
Skill package and signing semantics must match [`ori-specs`](https://github.com/ori-platform/ori-specs).
Do not invent fields outside the contracts.

5. `HUB-5` No secret material in storage.
Store author public keys and signatures only. Never store private keys.

6. `HUB-6` Optional scanners are fail-closed for listing.
If malware scanning is configured and fails, the skill must remain pending review.
If scanning is disabled, record that state explicitly.

7. `HUB-7` Local storage must be path-safe.
Skill names, versions, and upload filenames must not escape the configured
storage root.

8. `HUB-8` Never execute community skill code.
The Hub may inspect YAML metadata and tarball bytes. It must never import, run,
or sandbox community `hooks.py`; execution belongs only to [`ori-runtime`](https://github.com/ori-platform/ori-runtime).

9. `HUB-9` Runtime validation coupling must be version-pinned.
Any direct import from runtime SkillLoader requires an integration test matrix
against supported runtime versions.

## Verification

```bash
pre-commit run --all-files
pytest -q
```

## Layout

```text
hub/core/          pure contract and review logic
hub/security/      signing and verification
hub/storage/       tarball persistence backends
hub/integrations/  optional scanners and external services
hub/web/           FastAPI routes and app assembly
```
