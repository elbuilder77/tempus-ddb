# Onboarding corrections — 2026-09-08

This records implementation and local validation against
`Auditoria_UX_Tempus_DDB.md`. The GitHub App conversion remains paused. These
changes are local and unreleased; the public website has not been redeployed.

| Finding | Implemented behavior | Validation |
|---|---|---|
| Setup announces readiness too early | `init` reports initialization; `doctor` distinguishes workload configuration, supplies next steps and labels credential presence checks | CLI regression tests |
| First action requires assembling examples | Packaged `quickstart` configures identities/policy, runs a local file effect and persists verifiable evidence; GitHub trial preparation and real execution are separate commands | Wheel installation and completed local action; fake GitHub transport for success/UNKNOWN/denial/replay tests |
| MCP defaults disagree with documentation | `TEMPUS_WORKSPACE` and `TEMPUS_DB_PATH` are honored; autonomous `db` is optional; missing databases fail explicitly | Empty-history registry lookup plus actual stdio MCP connection using generated configuration |
| Recorded states appear authoritative when evidence is altered | Summary labels recorded authorization/execution and explicitly warns that altered data is untrusted and no new action occurred | Chromium alteration/restoration interaction and screenshots |
| Lost action ID blocks investigation | `actions` finds IDs by agent/resource/date and shows recorded states separately from integrity | Persistent-trial/history tests |
| Recovery is unclear | Continuous guide covers setup, denial, expiry, failure, missing receipts, UNKNOWN and invalid evidence | Guided execution tests include denial, UNKNOWN and no automatic replay |
| Header covers anchor title / restoration button loses contrast | Reserved anchor offset and removed overriding transparent background | Desktop anchor measured clear of header; unfocused primary button contrast 14.25:1; Enter restores VERIFIED |
| Protocol precedes a recognizable task | Homepage starts with an authorized issue use case; first-action recipe precedes protocol/contracts; demo leads with an issue description | Desktop and 390px browser inspection; no horizontal overflow on three pages |

## Correction to the original diagnosis

The current native core installs an active `tempus.baseline.v1` when the Gate is
registered. A fresh `init` therefore did not necessarily fail the old
`active_policy` check. The actual gap was that this permissive baseline could
pass diagnostics without an explicit workload policy. The new `workload_policy`
check fails that configuration. No authorization/receipt wire format changed.

## Checks completed

- Python suite: **83 passed**, including the real MCP stdio client/server test.
  Windows pipes/temporary-directory tests ran outside the restricted sandbox.
- Ruff and Bandit: passed. Dependency lock consistency and diff whitespace checks:
  passed.
- Static site validator: three pages, local references and original/altered/
  partial cryptographic verification cases passed.
- Built and installed a Windows abi3 wheel. Confirmed the imported package path
  was the wheel installation directory, then completed `quickstart` from another
  directory: `ALLOWED`, `SUCCEEDED`, `VERIFIED`.
- Local Chromium: altered evidence warning, restoration with Enter, unfocused
  button colors, anchor clearance and 390px overflow checks passed. Screenshots
  were inspected locally.

## Limits

No real GitHub issue was created. No Claude/Cursor application UI was tested;
the MCP protocol itself was exercised. Mobile checks used a simulated viewport,
not a physical device. This is not an accessibility certification. Multi-process
credential isolation remains a deployment requirement; the walkthrough is an
operator-run development environment. Additional interactive blocked/expired/
unknown scenarios in the browser demo remain future work.

No release, push, merge, public deployment or GitHub App registration was made.

## Recovery follow-up — 2026-09-09

The disaster-recovery guide, README, site guide and first-action guide now require
fresh event export from the restored Gate and independent checkpoint identity/
range checks, plus coordinated snapshots and reconciliation of each executor's
consumption state. A Gate checkpoint is not proof of executor completeness.

Three additional recovery tests passed: archived files verify despite a stale
restored Gate while a fresh export fails; restored executor consumption blocks
replay and its completed outcome can be committed without repeating the effect;
restored STARTED consumption becomes signed UNKNOWN and remains consumed.
No automatic reconstruction of lost executor state was implemented or claimed.
