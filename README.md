# hugmesh-owncast-bff-api

Backend-for-frontend that governs **who is allowed to broadcast** on
[Owncast](https://owncast.online) — the open-source, self-hosted live video
streaming server — as an optional service inside the [HugMesh](https://github.com/hugmesh)
platform.

This service is the **may-broadcast governance plane**, not the media plane. It
decides grants, timeouts and bans, per-streamer visibility, and moderation. It
carries no video. The default answer is no. It is a sibling of
[`hugmesh-wiki-bff-api`](https://github.com/hugmesh/hugmesh-wiki-bff-api) and
[`hugmesh-forum-bff-api`](https://github.com/hugmesh/hugmesh-forum-bff-api) and
uses the same stack: Spring Boot 4.0 on Java 25, WebFlux, R2DBC Postgres,
Liquibase, and a Casdoor JWT resource server, in the package
`net.hugmesh.owncastbff`.

Its companion frontend is [`hugmesh-owncast-ui`](https://github.com/hugmesh/hugmesh-owncast-ui).

> **Status legend:** ✅ shipped (merged to `main`) · 🚧 in progress (open branch/PR,
> not yet merged) · 🔭 planned (designed, not yet built). See the
> [Roadmap](#roadmap) for everything not yet on `main`.

## Contents

- [Status](#status)
- [What this service owns](#what-this-service-owns)
- [The `owncast_grant` overlay and `OwncastBroadcastGuard`](#the-owncast_grant-overlay-and-owncastbroadcastguard)
- [`owncast_stream` self-visibility](#owncast_stream-self-visibility-bffowncastuserstream)
- [Moderation surface](#moderation-surface-bffowncastmod)
- [Endpoint surface](#endpoint-surface)
- [Role model](#role-model)
- [Build, test and CI](#build-test-and-ci)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Status

This is the state of `main`: the source layout, the Liquibase changelogs, and the
`@SpringBootTest` / `@DataR2dbcTest` / `@WebFluxTest` / security-slice suites
under `src/test`.

- ✅ **Shipped and tested**:
  - the `owncast_grant` broadcast grant/timeout/ban overlay, with
    `OwncastBroadcastGuard` default-deny enforcement;
  - `owncast_stream` owner-controlled self-visibility (get/upsert plus a gated
    public/internal flip), with a `playbackUrl` that stays `null` until an
    operator configures the URL template;
  - the `/bff/owncast/mod` moderation surface (list/hide/ban(kill)/restore) with
    its own append-only `owncast_moderation_audit` journal;
  - database-generated UUID primary keys on all three tables;
  - hardened OWASP/NIST response headers;
  - an opt-in multi-issuer (per-brand Casdoor) resource server that fails closed
    on an unknown issuer;
  - Spring Boot 4.0.7 on Java 25 (inherited from `hugmesh-parent` 2.8.0, the
    parent named in `pom.xml`; the Dockerfile stages are `eclipse-temurin:25-*`);
  - a centralized OWASP pen-test CI stage (SCA + DAST, non-blocking);
  - cross-repo: `hugmesh-mod-bff-api` writes `owncast.hide` / `owncast.kill` /
    `owncast.restore` rows to its central `mod_action` ledger (its changelog
    `010`). This repo needed no code change for that.
- 🔭 **Known gaps** (designed, no code yet):
  - the per-streamer provisioning effector and streamer-ConfigMap reconciler,
    which would turn a broadcast grant into a per-streamer Owncast Deployment;
  - the `sd-owncast-player` federated video card kind;
  - a streamer/instance-lifecycle management UI;
  - the generator/devops per-domain service-enable.

  See the [Roadmap](#roadmap). The comment in Liquibase changelog `005` flags the
  reconciler, the ApplicationSet feed and the stream-key mint as deferred; nothing
  in this repo flags the other gaps. GPU node pinning and the default-off switch
  already ship in the generator (see [Role model](#role-model)).

## What this service owns

This service is the **may-broadcast governance plane**, not the media plane. The
Owncast media server is separate from this BFF. RTMP ingest is on `:1935`
(tailnet-only, never public). HLS playback is on `:8080` (behind the gateway).

Today the generator deploys one shared Deployment, `hugmesh-owncast`
(`replicas: 1`, `specs/cluster/manifests/owncast/deployment.yaml`). The Owncast
server, this BFF and `hugmesh-owncast-ui` run as three containers in one pod, on
an `emptyDir` data volume.

The design target is different. Owncast takes one broadcaster per instance, so the
platform is meant to run one Owncast Deployment per approved streamer, each with
its own `/app/data` volume and stream key, provisioned on grant. That provisioning
is not built (see the [Roadmap](#roadmap)).

The browser-to-governance path, alongside the separate media plane:

```mermaid
flowchart TD
    browser["Browser (owncast-ui)"]
    obs["OBS / RTMP client"]
    gw["fe-gateway (route-access + ROLE_OWNCAST floor)"]

    subgraph bff["THIS BFF — may-broadcast GOVERNANCE plane (shipped)"]
        admin["/bff/owncast/admin/access<br/>ADMIN | SUPERADMIN — grant/timeout/ban/restore"]
        super["/bff/owncast/superadmin/access<br/>SUPERADMIN — list-all + history"]
        mod["/bff/owncast/mod<br/>MOD | ADMIN | SUPERADMIN — list/hide/ban(kill)/restore"]
        userstream["/bff/owncast/user/stream<br/>ROLE_OWNCAST — get/upsert + visibility flip"]
        guard{{"OwncastBroadcastGuard<br/>default-deny, ban &gt; grant, SUPERADMIN exempt"}}
        grant[("owncast_grant (004)<br/>broadcast/banned overlay")]
        stream[("owncast_stream (005)<br/>per-streamer self-visibility")]
        audit[("owncast_moderation_audit (006)<br/>append-only mod journal")]
    end

    subgraph media["Media plane — Owncast (NOT this BFF); one shared Deployment today, per-streamer planned"]
        rtmp["Owncast :1935 RTMP ingest (tailnet-only)"]
        hls["Owncast :8080 HLS playback (behind gateway)"]
    end

    modbff["central mod-bff /bff/mod/owncast/**<br/>owncast.hide/kill/restore → mod_action ledger"]

    subgraph planned["Roadmap — not yet shipped"]
        effector["provisioning effector + streamer-ConfigMap reconciler<br/>ApplicationSet feed + stream-key Secret mint"]
        card["sd-owncast-player federated video card kind"]
    end

    browser --> gw
    gw --> admin
    gw --> super
    gw --> mod
    gw --> userstream
    admin --> grant
    super --> grant
    mod --> grant
    mod --> stream
    mod --> audit
    userstream --> stream
    userstream -. "PUBLIC flip + playbackUrl" .-> guard
    guard --> grant

    obs -. tailnet .-> rtmp
    browser -. HLS .-> hls
    stream -. drives .-> effector
    effector -. provisions .-> rtmp
    stream -. feeds .-> card
    modbff -- "drives (caller's bearer forwarded)" --> mod

    classDef planned stroke-dasharray:4,stroke:#888
    class effector,card planned
```

RTMP ingest and HLS playback never touch this BFF. They run on the Owncast server,
reached over the tailnet or the gateway. The dashed nodes above are
[roadmap](#roadmap) items, not yet on `main`.

## The `owncast_grant` overlay and `OwncastBroadcastGuard`

The broadcast grant/timeout/ban overlay is cloned from the wiki-bff `wiki_access`
(004) overlay, with `read` swapped for `broadcast`:

- **`owncast_grant`** (Liquibase `004-owncast-grant.xml`) — the desired-state table:
  `access_type ∈ {broadcast, banned}`, `state ∈ {active, revoked}` (rows are never
  deleted, so history stays for audit), `expires_at` (NULL = permanent, a future
  timestamp = a timeout that auto-restores; a timeout is a `banned` row with a
  future `expires_at`), a partial unique index on active
  `(domain, user_subject, access_type)` (PostgreSQL only), and domain scoping
  throughout.
- **`OwncastBroadcastGuard.assertCanBroadcast`** — the default-deny enforcement
  point every broadcast path depends on. Decision order:
  1. SUPERADMIN → **allow** at once (exempt from ban).
  2. Load the principal's active, non-expired `owncast_grant` rows for their brand.
  3. An active ban row → **403**, even if a broadcast grant also exists (ban beats
     grant).
  4. An active `broadcast` grant → **allow**.
  5. No qualifying grant → **403**.

  Wiki read access has a static role floor (`ADMIN` | `SUPERADMIN` | `MOD` with
  `WIKI`). Broadcasting has none: it is grant-only by design, with no role-level
  bypass.
- **`OwncastBroadcastController`** — exposes
  `/bff/owncast/admin/access` for grant/timeout/ban/restore (`ADMIN` | `SUPERADMIN`):
  `POST /grant`, `POST /timeout`, `POST /ban`, and
  `DELETE /{accessType}/{userSubject}` (`accessType` is `broadcast` or `banned`;
  the row is revoked, not deleted). It exposes `/bff/owncast/superadmin/access`
  for list (`GET`) and history (`GET /{userSubject}/history`) (`SUPERADMIN`).
- **`ROLE_OWNCAST`** — the base service role, a sibling of `ROLE_WIKI` / `ROLE_FORUM`.

## `owncast_stream` self-visibility (`/bff/owncast/user/stream`)

This is the streamer-facing counterpart to the admin-controlled `owncast_grant`
overlay. A streamer can read and write only their **own** stream. The server
derives the owner (`== jwt.sub`) and brand (`== validated issuer`); request fields
never supply them.

- **`owncast_stream`** (Liquibase `005-owncast-stream.xml`) — one row per
  `(domain, user_subject)` (a composite `UNIQUE` constraint: one stream per
  streamer per brand), with `title` / `description` and a `visibility` flag.
  `visibility CHECK IN ('public','internal')` with `DEFAULT 'internal'`. This fails
  closed: a new stream starts brand-internal and goes public only when the
  streamer flips it.
- **`OwncastStreamController`** under `/bff/owncast/user/stream`:
  - `GET` — the caller's own stream (404 if none yet). The response carries a
    **gated `playbackUrl`**, the per-instance Owncast HLS endpoint, formatted by
    `OwncastPlaybackUrlResolver` from `owncast.playback.url-template`. It is filled
    in only when the gate that governs going public allows the caller (active grant
    and not banned, SUPERADMIN exempt). The template is unset by default, so the
    field is `null` until an operator sets it. A denied caller never sees the URL.
  - `PUT` — create or update the caller's own `title` / `description`. A first
    upsert creates the stream with `visibility=internal`; only the visibility
    endpoint changes visibility.
  - `PUT /visibility` — flip the caller's own visibility between `internal` and
    `public`.
- **The critical rule:** a flip to **public** is allowed only while the owner
  holds an active broadcast grant. `OwncastStreamService.setVisibility` calls
  `OwncastBroadcastGuard.assertCanBroadcast` before writing and passes on any 403
  the guard raises (default-deny; an active ban blocks even a grantee; SUPERADMIN
  is exempt). A flip to **internal** is always allowed, unguarded. This check needs
  the database, so it lives in the service layer, not the path matcher: a static
  SpEL expression cannot query the database.

The public-flip decision sequence:

```mermaid
sequenceDiagram
    participant C as Browser (streamer)
    participant SC as SecurityConfig<br/>(path gate)
    participant SVC as OwncastStreamService
    participant G as OwncastBroadcastGuard
    participant DB as owncast_grant (DB)

    C->>SC: PUT /bff/owncast/user/stream/visibility {visibility:"public"}
    SC-->>C: 401/403 if not ROLE_OWNCAST
    SC->>SVC: setVisibility("public", principal)
    SVC->>G: assertCanBroadcast(principal)
    G->>DB: load active non-expired grants for (domain, subject)
    DB-->>G: grant rows
    alt SUPERADMIN
        G-->>SVC: ALLOW (exempt)
    else active BAN row found
        G-->>SVC: 403 Forbidden
        SVC-->>C: 403
    else active broadcast grant found
        G-->>SVC: ALLOW
        SVC->>DB: UPDATE owncast_stream SET visibility='public'
        SVC-->>C: 200 OK
    else no qualifying grant
        G-->>SVC: 403 Forbidden
        SVC-->>C: 403
    end
```

- **Path gate:** `SecurityConfig` restricts `/bff/owncast/user/**` to
  `hasRole('OWNCAST')`. The `ROLE_OWNCAST` floor is what lets a domain user reach
  the Owncast user surface at all.

## Moderation surface (`/bff/owncast/mod`)

A moderator (`MOD` | `ADMIN` | `SUPERADMIN`) lists their brand's streams and acts
on a target owner's stream. The authority is the MOD role plus a domain match, not
ownership. The server derives the moderator's brand and identity from the JWT, and
every action is scoped to `(moderatorDomain, ownerSubject)`.

- **`owncast_moderation_audit`** (Liquibase `006-owncast-moderation-audit.xml`) —
  an append-only journal: who (`actor_subject`) did what
  (`action CHECK IN ('kill','hide','restore')`) to whom (`target_subject`), in
  which brand (`domain`), why (`reason`), and when.
- **`OwncastModerationController`** under `/bff/owncast/mod`:
  - `GET /streams` — list the moderator's brand streams (each row carries the
    owner's active broadcast-ban flag).
  - `POST /streams/{ownerSubject}/hide` — force the target's stream
    `visibility=internal`.
  - `POST /streams/{ownerSubject}/ban` — the "kill" verb: write an active
    `owncast_grant(banned)` row (so the existing `OwncastBroadcastGuard`
    ban-over-grant precedence blocks the owner's public broadcast flip) and force
    the stream internal. The audit journal records this action as `kill`. It
    preserves the audit trail and never hard-deletes anything.
  - `POST /streams/{ownerSubject}/restore` — atomically moves (compare-and-swap)
    the active broadcast ban row from `active` to `revoked` (the row stays for
    audit). It does not republish the stream.
- **Reuse, not a parallel mechanism:** ban and restore reuse `owncast_grant
  (access_type=banned)`, and hide reuses `owncast_stream`. `owncast_moderation_audit`
  is a local trace on top of both. The moderation verbs are kill/hide/ban/restore
  only. A MOD never reaches the admin/superadmin governance prefixes (separate
  controllers under higher path gates) and never grants broadcast access.
  Moderation is pinned to one brand with no all-brands bypass: a SUPERADMIN
  moderates inside the `default` brand only.
- **Database-generated UUID primary keys** (Liquibase
  `007-db-generated-uuid-pks.xml`) — on all three tables
  (`owncast_grant` / `owncast_stream` / `owncast_moderation_audit`), Postgres
  mints the `id` through a `(gen_random_uuid())::text` column default, and the
  code reads it back with `INSERT ... RETURNING id`. This replaces a Java-side
  `UUID.randomUUID()` (the same pattern as `hugmesh-mod-bff-api`). Column and `@Id`
  types are unchanged; only the source of the id moved to the database.
- **Path gate:** `SecurityConfig` restricts `/bff/owncast/mod/**` to
  `hasAnyRole('MOD','ADMIN','SUPERADMIN')`, and a method-level `@PreAuthorize`
  checks again (defense in depth).

## Endpoint surface

The four prefixes, gated in `SecurityConfig`:

| Prefix | Role gate (path matcher) | Owns |
| --- | --- | --- |
| `/bff/owncast/superadmin/**` | `SUPERADMIN` | list-all + history (`OWNCAST_MANAGE`) |
| `/bff/owncast/admin/**` | `ADMIN` \| `SUPERADMIN` | grant/timeout/ban/restore (`OWNCAST_GOVERN`) |
| `/bff/owncast/mod/**` | `MOD` \| `ADMIN` \| `SUPERADMIN` | list/hide/ban (kill)/restore |
| `/bff/owncast/user/**` | `OWNCAST` | own stream + self-visibility |
| `/bff/owncast/**` | `.authenticated()` | catch-all floor; the gateway also enforces the `ROLE_OWNCAST` route-access check upstream |

`OwncastBroadcastGuard` and `OwncastStreamService` enforce the per-principal
broadcast decision (active grant and no active ban, SUPERADMIN exempt) and the
public-flip gate, not the path matcher, because a static SpEL expression cannot
query the database.

`SecurityConfig` also wires:

- A Casdoor JWT-to-authority converter, with a reserved-prefix injection guard and
  one issuer-derived `DOMAIN_<x>` authority per token.
- An opt-in multi-issuer resource server: one Casdoor instance per brand. An
  unknown `iss` claim gets 401.
- A SUPERADMIN-only role hierarchy (`SUPERADMIN` > `ADMIN`, `MOD`, `USER`).
- An optional MFA floor: `app.mfa.enabled` (default `false`) and
  `app.mfa.freshness-window` (default 600000 ms), passed to the shared Casdoor
  converter.
- The OpenAPI spec and Swagger UI, public under the `dev`/`test` profiles (so
  `ng-openapi-gen` can fetch the spec without credentials) and restricted to
  `ADMIN`/`SUPERADMIN` in production.

Every chain also sets defense-in-depth API security headers (OWASP/NIST): a
no-content `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
`Referrer-Policy: no-referrer`, and Spring's reactive secure defaults
(`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control`
no-store). HSTS and Permissions-Policy are left out on purpose. They belong only at
the gateway's TLS entry point, not on a plaintext intra-mesh JSON hop.

## Role model

- **SUPERADMIN** — `OWNCAST_MANAGE`; has cross-domain visibility on the grant
  surfaces (not on the moderation surface); exempt from the broadcast ban.
  Per-domain service-enable by SUPERADMIN is planned, not built — see the
  [Roadmap](#roadmap).
- **ADMIN (own brand)** — `OWNCAST_GOVERN`: grant/timeout/ban/restore
  may-broadcast access (`/bff/owncast/admin/access`).
- **MOD** — moderation lives here at `/bff/owncast/mod` (list/hide/ban/restore;
  ban/restore reuse `owncast_grant`). The cross-repo `hugmesh-mod-bff-api`
  `ModActionType owncast.*` wiring into the central mod-action ledger is
  shipped: its `/bff/mod/owncast/streams/{owner}/hide|kill|restore` drives
  these effector endpoints (`kill` calls this service's `/ban`). The caller's
  bearer is forwarded, so this service re-derives the moderator's identity and
  brand from the same validated token. Mod-bff records the matching
  `owncast.hide`/`owncast.kill`/`owncast.restore` row in the central `mod_action`
  ledger (mod-bff changelog `010`). An action driven through the central surface
  lands in both records. An action taken directly here journals into the local
  `owncast_moderation_audit` only.
- **USER** — may broadcast only if granted (default-deny). May read and upsert their
  own stream (title/description) and flip its visibility between `internal` and
  `public` via `/bff/owncast/user/stream`. A flip to public is allowed only
  while the user holds an active broadcast grant (default-deny; SUPERADMIN
  exempt).

The service is **off by default** and is GPU-pinned (x86 + GPU dependent). The
generator ships both: the app is marked default-off
(`specs/cluster/apps/52-owncast.yaml`) and the pod carries the node selector
`kubernetes.io/arch: amd64` plus `hugmesh.net/compute: gpu`
(`specs/cluster/manifests/owncast/deployment.yaml`). The per-domain enable path
is on the [Roadmap](#roadmap).

## Build, test and CI

Build and test: `./mvnw -DskipITs test`. CI runs on GitLab (`.gitlab-ci.yml`):
`test` → `build` → `pentest` stages. A manual-only GitHub workflow,
`.github/workflows/release.yml` (`workflow_dispatch`), builds the image and pushes
it to GHCR.

The full-context `@SpringBootTest` integration tests extend the shared
`net.hugmesh.commons.testsupport.PostgresTestSupport` (from the
`hugmesh-commons` test-jar). It boots a real per-class **Testcontainers**
Postgres, so `./mvnw test` needs a Docker daemon (the `test:unit` CI
job runs a `docker:dind` service). The `@DataR2dbcTest` repository/service
slices extend the same base and run the production Liquibase changelog on that
Postgres, through `PostgresSliceTestConfig`. They need it: changelog `007` uses
`gen_random_uuid()` and `INSERT ... RETURNING`, which an H2 store cannot run.
`OpenApiSpecDumpTest` asserts that the committed
`src/main/resources/openapi/openapi.json` matches the live API, and it fails on
drift (the server URL is normalized so the random test port never moves the file).
To refresh the file, run
`./mvnw -Dtest=OpenApiSpecDumpTest -Dopenapi.spec.write=true test` and commit the
result. The CI job also runs `git diff --exit-code` after the tests, so a test that
rewrites a committed file fails the build.

The multi-issuer (per-brand Casdoor) security-slice tests
(`SecurityConfigPathGateSliceTest`, `MultiIssuerSecuritySliceTest`) follow a
documented, reusable no-network pattern. See
[`docs/testing/MULTI-ISSUER-SLICE.md`](docs/testing/MULTI-ISSUER-SLICE.md) for
what the slice asserts and why fail-closed is the property that matters.

- **Pen-test stage** — the centralized OWASP harness is wired in with an
  `include:` of the generator's `pentest-stage.gitlab-ci.yml`: a non-blocking
  (`allow_failure`) `pentest:sca` job (OWASP Dependency-Check SCA) and a
  `pentest:dast` job (authenticated ZAP baseline DAST), run on the default
  branch and merge requests. `make pentest` runs the same SCA locally (plus
  optional DAST against `$DAST_TARGET_URL`).
- 🔭 Further harness additions (nuclei templates, k6 load testing) belong to the
  generator template and are tracked there. This repo uses the centralized
  include, so they arrive as the generator template adds them.

## Roadmap

Owncast as an optional service is shipped at the platform level (this BFF and the
paired `hugmesh-owncast-ui` are merged). These per-streamer media-plane and
cross-repo pieces are not on `main` in this repo:

- 🔭 **Per-streamer provisioning effector and streamer-ConfigMap reconciler** —
  turning an `owncast_grant` broadcast grant into a per-streamer Owncast
  Deployment: the ApplicationSet feed and stream-key `Secret` mint. The comment in
  Liquibase changelog `005-owncast-stream.xml` flags this as a deferred
  follow-up gated on the generator.
- 🔭 **`sd-owncast-player` federated video card kind** — per-user federated video
  remotes, templated like profile cards, driven by this BFF's `owncast_stream`
  public-visibility data (already built) plus the card kind and reconciler, which
  are still to come.
- 🔭 **Management UI** for streamer/instance lifecycle, beyond the governance and
  moderation views already in `hugmesh-owncast-ui`.
- 🔭 **Generator/devops** — per-domain SUPERADMIN service-enable. The GPU
  node-affinity / x86-and-GPU-pinned constraint and the default-off switch already
  ship in the generator; only the per-domain enable is open.
- ✅ **Cross-repo `hugmesh-mod-bff-api` `ModActionType owncast.*` wiring** —
  shipped in mod-bff (its changelog `010` and `/bff/mod/owncast/**` surface). A
  moderator who drives hide/kill/restore through the central mod surface hits this
  BFF's `/bff/owncast/mod` effector endpoints (`kill` posts to `/ban`; the
  caller's bearer is forwarded) and gets an `owncast.hide`/`owncast.kill`/`owncast.restore`
  row in the central `mod_action` ledger. This repo needed no code change, because
  the effector surface already existed. Scope note: an action taken directly at
  this BFF's `/bff/owncast/mod` (for example, from `hugmesh-owncast-ui` today)
  journals into the local `owncast_moderation_audit` only. The central row is
  written only when the action is driven through mod-bff (the moderation UI's
  central surface).

Items move from 🔭 planned → 🚧 in progress (open branch/PR) → ✅ shipped. This
section is trimmed as each lands on `main`.

## Contributing

Issues and pull requests are welcome. To propose a change to the governance model
(grant/ban precedence, visibility gating, moderation scope), open an issue first
so we can settle the design. This service is default-deny on purpose, and changes
here ripple into `hugmesh-owncast-ui` and `hugmesh-mod-bff-api`.

Before opening a PR:

- Run `./mvnw -DskipITs test` locally (the Testcontainers-backed integration tests
  need a Docker daemon).
- Keep the OpenAPI spec in sync. `OpenApiSpecDumpTest` fails the build if
  `src/main/resources/openapi/openapi.json` drifts from the code.
- Follow the existing package layout (`access`, `stream`, `mod`, `config`,
  `security`, `web`). If you touch authentication or authorization, follow the
  security-slice test pattern in
  [`docs/testing/MULTI-ISSUER-SLICE.md`](docs/testing/MULTI-ISSUER-SLICE.md).

## License

Released under the [MIT License](LICENSE).
