# Multi-issuer security-slice — the reusable test pattern (owncast-bff-api)

This is the owncast-BFF's copy of a reference pattern also used across the other
HugMesh BFFs (originally built in
[`hugmesh-gateway`](https://github.com/hugmesh/hugmesh-gateway)) for proving
a Spring WebFlux OAuth2 resource server correctly handles per-brand (multi-issuer)
Casdoor tokens, with the security property that matters most: an unknown issuer
fails **closed** (401), and a token from one brand can never authenticate as
another.

The whole point is **determinism with no network and no live Casdoor**: each brand's
JWKS + OIDC discovery doc is served by a tiny in-process HTTP server bound to
`127.0.0.1`, so `ReactiveJwtDecoders.fromIssuerLocation(...)` validates real
RSA-signed tokens offline.

---

## What the slice asserts (the three keystones)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and the `DOMAIN_brandx` authority is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

Plus the cheap fail-closed neighbours: a **tampered signature** and a **garbage
bearer** both 401.

---

## The two reusable seams (copied from the gateway, package adjusted)

### 1. `TestIssuer` — `src/test/java/.../testsupport/TestIssuer.java`

Each instance generates a fresh RSA keypair, starts a JDK `HttpServer` on
`127.0.0.1:<random-port>` serving `/.well-known/openid-configuration` and
`/.well-known/jwks.json`, and exposes `issuerUri()` + `mint(subject, roleNames)`.
A token minted by issuer A is cryptographically valid **only** against issuer A's
manager — that is exactly the cross-brand isolation (c). Only dependency:
`nimbus-jose-jwt`, already transitive via `spring-boot-starter-oauth2-resource-server`.

### 2. `SecuritySliceSupport` — `src/test/java/.../config/SecuritySliceSupport.java`

Constructs this repo's real `SecurityConfig` filter chain
(`SecurityConfig(DomainRegistry, ObjectProvider<resolver>)`), wraps it in a
`WebFilterChainProxy`, and installs it as a `webFilter` on
`WebTestClient.bindToController(...)` — no full Spring Boot context is needed.
Because the owncast `SecurityConfig` exposes two profile-split chains, this
support exposes both `sliceClient(...)` (the prod `filterChain`,
`@Profile("!dev & !test")`) and `devSliceClient(...)` (the dev/test
`devFilterChain`), so the prod-vs-dev OpenAPI-spec gating can both be asserted.
Helpers: `provider(resolver)` (multi-issuer swap) and `absent()` (single-issuer
`o.jwt(...)` path).

---

## This repo's path-gate table (coarse `authorizeExchange` policy)

The `SecurityConfigPathGateSliceTest` covers the owncast-specific gating, which
is defense in depth atop the gateway's route-access check:

| Path prefix | Required | Notes |
|---|---|---|
| `/actuator/health`, `/actuator/health/**`, `/actuator/info` | `permitAll` | k8s/Docker probes need no token |
| `/bff/owncast/superadmin/**` | `hasRole('SUPERADMIN')` | MANAGE-ALL surface |
| `/bff/owncast/admin/**` | `hasAnyRole('ADMIN','SUPERADMIN')` | OWNCAST_GOVERN grant/ban |
| `/bff/owncast/user/**` | `hasRole('OWNCAST')` | streamer self-service floor |
| `/bff/owncast/mod/**` | `hasAnyRole('MOD','ADMIN','SUPERADMIN')` | moderation surface |
| `/bff/owncast/**` | `.authenticated()` | the floor |
| spec paths (`/v3/api-docs/**`, `/swagger-ui/**`, ...) | **prod: `hasAnyRole('ADMIN','SUPERADMIN')`** / dev+test: `permitAll` | the prod-gating gap the slice asserts |
| anything else | `.authenticated()` | `anyExchange().authenticated()` |

> **Note:** `ROLE_OWNCAST` is a sibling role — there is no `SUPERADMIN > OWNCAST`
> hierarchy edge, and path matchers don't apply the `@PreAuthorize` role hierarchy
> anyway — so a SUPERADMIN token does *not* satisfy the `/bff/owncast/user/**`
> gate. The slice documents this with `superadmin_forbiddenOn_userStreamerSurface`.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set yields **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` surfaces a 401 **before any authority
is emitted** — there is no fallback "default" manager that could accept an unlisted
brand. Scenario (b) is the regression guard that keeps it that way: a future refactor
that introduces a default-accept (or routes an unknown `iss` to brand-X's manager)
turns (b) red.
