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

---

## Supply Chain Security Invariants

These rules apply to every AI coding agent modifying this repository. The Hub
distributes skills that execute on physical-hardware runtimes — supply chain
integrity here directly affects device safety.

1. Never add `pull_request_target` workflows that checkout or execute untrusted
   PR code. Use `pull_request` for fork PR workflows.

2. Every GitHub Actions workflow must declare explicit least-privilege
   permissions. Normal CI uses `contents: read` and `id-token: none`.

3. `id-token: write` is allowed only in a dedicated release job in `release.yml`.
   It must never appear in `ci.yml`.

4. Release jobs must never restore dependency caches (`actions/cache`, package
   manager caches, or setup action cache flags). Cache poisoning was a key part
   of the TanStack May 2026 supply-chain attack.

5. GitHub Actions must be pinned to full commit SHAs. Mutable tags such as
   `@v4`, `@v5`, `@main`, and `@master` are forbidden. Add a human-readable
   version comment next to each SHA.

6. Never download and execute remote scripts in CI without hash or signature
   verification. `curl URL | bash` and equivalent patterns are forbidden.

7. Python installs in CI must use hash-locked requirements files with
   `--require-hashes`. Do not use `pip install -r requirements-dev.txt` without
   hashes in CI.

8. Community skills with Tier C or D actuation remain `pending_review` regardless
   of SLSA provenance status or author reputation. Valid provenance does not imply
   safe code — this is the primary lesson of the TanStack May 2026 incident.

9. Ed25519 signing implementations use `cryptography`, not PyNaCl. This ensures
   interoperability with ori-runtime's community skill signature verification path.

10. Run `scripts/check_workflows.py` before merging workflow or pre-commit
    configuration changes. The script fails on `pull_request_target`, mutable
    action refs, unauthorized `id-token: write`, remote script execution
    patterns, and remote pre-commit hooks not pinned to full commit SHAs.

11. The Hub must never execute community skill code (HUB-8). Inspection of YAML
    metadata and tarball bytes is permitted. Execution belongs only to ori-runtime
    under its sandbox and Tier C/D review gate.
