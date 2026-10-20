# Entitlement management (CIEM)

> **Enterprise edition only** (`ciem` flag). Keep this file off `main` and
> `enclave-oss`.

Cloud infrastructure entitlement management, scaled to one product: for each
project, show every path by which a person or a workload can reach each stage,
compare that with what they actually used, flag what is excessive, and let the
owner fix it in one click. Grants can be time-boxed so that standing access
becomes the exception.

Code: `infra/functions/lib/audit.ts` (recording), `lib/ciem.ts` (analysis,
pure), `admin/ciem.ts` (endpoints), `lib/access.ts` (expiry enforcement),
`web/src/pages/AccessReviewPage.tsx`.

## Building blocks

```
         vault calls, logins, runs
                    │
                    ▼
   ┌───────────────────────────────┐        ┌──────────────────────────┐
   │ AuditTable                    │        │ AccessTable              │
   │  events   (TTL, forensic)     │        │  MEMBER#  owners/members │
   │  USAGE#   rollups (no TTL)    │        │  TEAM#    team grants    │
   └───────────────┬───────────────┘        │  MACHINE# bindings       │
                   │                        └────────────┬─────────────┘
                   └──────────────┬──────────────────────┘
                                  ▼
                 buildEntitlements() → analyze() → utilization()
                                  │
                                  ▼
             GET /admin/projects/{p}/entitlements  (owner only)
             GET /admin/projects/{p}/audit         (owner only, paginated)
```

## Audit trail

`record()` writes, in one DynamoDB transaction:

1. **An event**
   - Key: `PROJECT#<p> / <timestamp>#<random>`.
   - Fields:
     - the principal and its kind (human, machine or runner), the stage, the
       action and the file
     - the external identity (`src`); for a run, the human it acts for (`actor`)
     - the source IP and user agent
   - Also indexed by principal on `gsi1`.
   - Expires after `auditRetentionDays` (default 90) via the table's TTL.
2. **A usage rollup**
   - Key: `USAGE#<p> / <actor>#<stage>`.
   - Holds `lastRead`, `lastWrite`, and `reads` and `writes` counts.
   - Has no TTL, so "last used" survives event expiry.

Recorded actions: `decrypt`, `generate`, `download`, `upload`, `delete`, `list`,
`workload.login`, `run.launch` and `run.stop`. Logins and stops are recorded as
events but don't count as use.

**Fail-closed.** The vault endpoints await `record()` *before* they call KMS
or mint a presigned URL. If the audit write fails, the request fails. An access
that couldn't be recorded doesn't happen.

**Runs act for a person.** A cloud run's reads are recorded with the runner as
principal and roll up under the human who launched it, so that person's
entitlement shows as used.

## Entitlements

An entitlement is one path from a principal to a set of stages:

| `via` | Principal | Stages | Access |
|---|---|---|---|
| `owner` | email | all | write |
| `member` | email | listed on the membership | write |
| `team:<t>` | each member of the team | listed on the team grant | write |
| `binding` | `machine:<p>/<id>` | listed on the binding | read or write |

The same person can appear several times, for example as a direct member and
through a team. Each path is reported separately because each has to be removed
separately.

Every entitlement carries its per-stage usage, its last use, and its expiry
(if any).

## Findings

Findings compare grants with use inside a look-back window (`ciemUnusedDays`,
default 30). A grant younger than the window is not judged on use. Owners are
never flagged, because ownership is the project, not a grant to prune.

| Rule | Severity | Trigger | One-click fix |
|---|---|---|---|
| `expired-grant` | low | expiry has passed; it no longer grants anything | revoke (remove the record) |
| `inactive` | high if prod, else medium | no read or write on any granted stage in the window | revoke |
| `unused-stage` | high for prod, else medium | active elsewhere, not on this stage | remove that stage |
| `unused-write` | high if prod, else medium | machine binding with write access that only read | make read-only |
| `standing-prod` | low | human with prod access and no expiry | expire in 7 days |
| `any-branch` | high if prod, else medium | GitHub binding that pins neither `ref` nor `environment` | (edit the binding) |
| `wildcard-prod` | medium | prod binding with a `*` in a claim pattern | (edit the binding) |
| `all-stages` | low | binding covers every configured stage | (split per stage) |

Team-derived entitlements show up in findings but get no one-click fix. That
would mean changing the team, which affects other projects too.

Fixes go through the normal member and binding endpoints. A fix is therefore
exactly as reversible, and as audited, as the same edit made on the settings
page. Editing a binding gives it a new `rev`, so the binding's machine tokens
stop working at once.

## Utilization

```
utilization = used (principal, stage) pairs / granted (principal, stage) pairs
```

This is counted over the window, excluding owners and expired grants. It's a
single number to track over time: 100% means every grant was used; a low value
means access has accumulated.

## Time-boxed grants (just-in-time access)

Members and machine bindings accept `expiresInHours` (1–720). It's stored as an
ISO `grantExpiresAt`. The expiry is enforced in the authorization path itself:
- `canAccess` for humans
- `authorize` for machine tokens
- `permissionsFor` for the project list

Nothing has to run for an expiry to take effect, and an expired grant can't be
used even if no one removes it. The record stays visible as `expired-grant`
until someone cleans it up.

Upserting a member or binding without `expiresInHours` makes the grant standing
again. The access-review fixes keep an existing expiry when they edit a grant.

## Limits

- **Single-project view.** There's no cross-project report per person.
- **Team grants have no expiry.** Time-boxing applies to direct members and
  bindings.
- **Usage is only what this service sees.** A secret copied out of the vault and
  used elsewhere doesn't show up. That's another reason to deliver secrets with
  `exec`, `run` or the cloud runner rather than exporting them.
- **Owner-only.** The endpoints and page are restricted to the project owner;
  members can't see others' entitlements.
