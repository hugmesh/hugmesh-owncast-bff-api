# Multi-issuer security-slice — the reusable test pattern (owncast-bff-api)

This is the owncast BFF's copy of a reference pattern shared by the HugMesh BFFs
(first built in [`hugmesh-gateway`](https://github.com/hugmesh/hugmesh-gateway)).
It proves that a Spring WebFlux OAuth2 resource server handles per-brand
(multi-issuer) Casdoor tokens correctly, and it pins the property that matters
most: an unknown issuer fails **closed** (401), and a token from one brand can
never authenticate as another.

The point is **determinism with no network and no live Casdoor**. A small
in-process HTTP server, bound to `127.0.0.1`, serves each brand's JWKS and OIDC
discovery document. So `ReactiveJwtDecoders.fromIssuerLocation(...)` validates real
RSA-signed tokens offline.

---

## What the slice asserts (the three keystones)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and the `DOMAIN_brandx` authority is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

The slice also checks the cheap fail-closed cases. A **tampered signature**, a
**garbage bearer** and a **missing bearer** all return 401. A brand-X token whose
`permissions` claim carries `DOMAIN_brandy` or `ROLE_SUPERADMIN` gains neither
authority, because the converter strips reserved prefixes
(`crossUser_permissionsCannotForgeForeignDomain`).

---

## The two reusable seams (copied from the gateway, package adjusted)

### 1. `TestIssuer` — `src/test/java/.../testsupport/TestIssuer.java`

Each instance generates a fresh RSA keypair and starts a JDK `HttpServer` on
`127.0.0.1:<random-port>`. The server serves `/.well-known/openid-configuration`
and `/.well-known/jwks.json`. The instance exposes `issuerUri()` and
`mint(subject, roleNames)`. A token minted by issuer A is cryptographically valid
**only** against issuer A's manager. That is the cross-brand isolation of (c). The
only dependency is `nimbus-jose-jwt`, already transitive via
`spring-boot-starter-oauth2-resource-server`. `mintWithClaims(subject, claims)`
mints a token with arbitrary claims, for example a forged `permissions` list.

### 2. `SecuritySliceSupport` — `src/test/java/.../config/SecuritySliceSupport.java`

It builds this repo's real `SecurityConfig` filter chain with
`new SecurityConfig(registry, tenantResolver, false, 600000L)`: the
`DomainRegistry`, an `ObjectProvider` of the resolver, the `app.mfa.enabled` flag,
and the `app.mfa.freshness-window` in milliseconds. It wraps the chain in a
`WebFilterChainProxy` and installs it as a `webFilter` on
`WebTestClient.bindToController(...)`. No full Spring Boot context is needed.

The slice also needs `src/test/java/net/hugmesh/commons/config/TenancyResolvers.java`.
`TenancyResourceServerConfig` lives in `hugmesh-commons`, and its resolver bean
method is package-private. This one-method class, in the same package under this
repo's test sources, lets the tests call it. Copy it with the other two files.

The owncast `SecurityConfig` exposes two profile-split chains. So the support
class has both `sliceClient(...)` (the prod `filterChain`,
`@Profile("!dev & !test")`) and `devSliceClient(...)` (the dev/test
`devFilterChain`). That lets the slice assert the prod-vs-dev OpenAPI-spec gating.
Helpers: `provider(resolver)` (multi-issuer swap) and `absent()` (single-issuer
`o.jwt(...)` path).

---

## This repo's path-gate table (coarse `authorizeExchange` policy)

`SecurityConfigPathGateSliceTest` covers the owncast-specific gating, which is
defense in depth on top of the gateway's route-access check:

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

> **Note:** `ROLE_OWNCAST` is a sibling role. There is no `SUPERADMIN > OWNCAST`
> hierarchy edge, and path matchers do not apply the `@PreAuthorize` role
> hierarchy anyway. So a SUPERADMIN token does *not* satisfy the
> `/bff/owncast/user/**` gate. The slice pins this with
> `superadmin_forbiddenOn_userStreamerSurface`.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`.
An `iss` outside that set gets **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` returns a 401 **before any
authority is emitted**. No fallback "default" manager exists that could accept an
unlisted brand. Scenario (b) guards that. A later refactor that adds a
default-accept, or routes an unknown `iss` to brand-X's manager, makes (b) fail.
