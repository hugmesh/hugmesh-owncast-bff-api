package net.hugmesh.owncastbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.owncastbff.testsupport.TestIssuer;

import java.util.List;

/**
 * Coarse PATH-GATE slice — the owncast {@link SecurityConfig} {@code authorizeExchange}
 * policy end-to-end through the real filter chain (replicated from the gateway
 * keystone). Today the role hierarchy + converter are unit-tested in isolation; this
 * proves the actual REQUEST-PATH gating + the prod-vs-dev OpenAPI-spec gating gap.
 *
 * <p>Asserts:
 * <ul>
 *   <li><b>ANONYMOUS DENY</b> — every {@code /bff/owncast/**} prefix 401s an anonymous
 *       caller (the floor + each role-gated prefix; the
 *       {@code anyExchange().authenticated()} catch-all);</li>
 *   <li><b>USER-SITUATIONAL ALLOW/DENY</b> — a {@code ROLE_OWNCAST} streamer reaches
 *       {@code /bff/owncast/user/**}; a plain {@code ROLE_USER} does not; SUPERADMIN —
 *       a SIBLING of OWNCAST, no hierarchy edge for path matchers — does NOT reach the
 *       streamer surface; SUPERADMIN reaches the superadmin/admin prefixes;</li>
 *   <li><b>PROD SPEC GATING (this repo's gap)</b> — the OpenAPI spec + Swagger UI are
 *       ADMIN/SUPERADMIN-only on the PROD chain (anonymous + plain user 401/403),
 *       but {@code permitAll} on the DEV/TEST chain (anonymous reaches them);</li>
 *   <li><b>PUBLIC PROBES</b> — {@code /actuator/health} + {@code /actuator/info} are
 *       reachable anonymously on both chains.</li>
 * </ul>
 *
 * <p>The path policy is auth-decoder-agnostic, so this slice drives tokens through the
 * multi-issuer resolver path (the only no-network decoder seam — backed by an
 * in-process {@link TestIssuer}); the {@code authorizeExchange} rules under test are
 * identical on the single-issuer path.
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private DomainRegistry registry;
    private ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver;
    private WebTestClient prod;   // SecurityConfig.filterChain (!dev & !test)
    private WebTestClient dev;    // SecurityConfig.devFilterChain (dev/test)

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        resolver = TenancyResolvers.tenantResolver(tenancy);
        prod = sliceClient(registry, provider(resolver), new ProbeController());
        dev = devSliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private WebTestClient.RequestHeadersSpec<?> as(WebTestClient c, List<String> roles, String path) {
        String token = issuer.mint("p-" + String.join("-", roles), roles);
        return c.get().uri(path).header("Authorization", "Bearer " + token);
    }

    // ── ANONYMOUS DENY — every owncast prefix + the floor ─────────────────────

    @Test
    void anonymous_deniedOn_everyOwncastPrefix() {
        for (String path : List.of(
                "/bff/owncast/superadmin/streams",
                "/bff/owncast/admin/grants",
                "/bff/owncast/user/stream",
                "/bff/owncast/mod/streams",
                "/bff/owncast/anything")) {
            prod.get().uri(path).exchange()
                    .expectStatus().isUnauthorized();
        }
    }

    @Test
    void anonymous_deniedOn_arbitraryGatedPath() {
        // anyExchange().authenticated() — an ungoverned, non-public path 401s anonymous.
        prod.get().uri("/api/whatever").exchange().expectStatus().isUnauthorized();
    }

    // ── USER-SITUATIONAL — the /bff/owncast/user/** OWNCAST floor ─────────────

    @Test
    void owncastStreamer_allowedOn_userSurface() {
        // ROLE_OWNCAST is the streamer self-service floor — reaches the controller (200).
        as(prod, List.of("owncast"), "/bff/owncast/user/stream").exchange()
                .expectStatus().isOk();
    }

    @Test
    void plainUser_forbiddenOn_userStreamerSurface() {
        // A plain authenticated principal (only the ROLE_USER floor) is NOT a streamer:
        // 403 on /bff/owncast/user/** (authenticated but lacks ROLE_OWNCAST).
        as(prod, List.of("someotherrole"), "/bff/owncast/user/stream").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void superadmin_forbiddenOn_userStreamerSurface() {
        // SECURITY SUBTLETY: ROLE_OWNCAST is a SIBLING role — there is no
        // SUPERADMIN > OWNCAST hierarchy edge, and path matchers do NOT apply the
        // @PreAuthorize role hierarchy anyway. So a SUPERADMIN token does NOT satisfy
        // hasRole('OWNCAST') at the path layer: 403. (SUPERADMIN governs streamers via
        // the superadmin/admin prefixes, not by impersonating the streamer surface.)
        as(prod, List.of("superadmin"), "/bff/owncast/user/stream").exchange()
                .expectStatus().isForbidden();
    }

    // ── USER-SITUATIONAL — admin / superadmin govern prefixes ─────────────────

    @Test
    void superadmin_allowedOn_superadminPrefix() {
        as(prod, List.of("superadmin"), "/bff/owncast/superadmin/streams").exchange()
                .expectStatus().isOk();
    }

    @Test
    void admin_forbiddenOn_superadminPrefix() {
        // /bff/owncast/superadmin/** is SUPERADMIN-only; a plain ADMIN is 403.
        as(prod, List.of("admin"), "/bff/owncast/superadmin/streams").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void admin_allowedOn_adminPrefix() {
        as(prod, List.of("admin"), "/bff/owncast/admin/grants").exchange()
                .expectStatus().isOk();
    }

    @Test
    void superadmin_allowedOn_adminPrefix_viaHierarchy() {
        // ROLE_SUPERADMIN > ROLE_ADMIN — but path matchers don't apply hierarchy; the
        // rule is hasAnyRole("ADMIN","SUPERADMIN") so SUPERADMIN is allowed EXPLICITLY.
        as(prod, List.of("superadmin"), "/bff/owncast/admin/grants").exchange()
                .expectStatus().isOk();
    }

    @Test
    void mod_allowedOn_modPrefix_butForbiddenOn_adminPrefix() {
        as(prod, List.of("mod"), "/bff/owncast/mod/streams").exchange().expectStatus().isOk();
        as(prod, List.of("mod"), "/bff/owncast/admin/grants").exchange().expectStatus().isForbidden();
    }

    @Test
    void owncastStreamer_forbiddenOn_modPrefix() {
        // A bare streamer is not a moderator: 403 on /bff/owncast/mod/**.
        as(prod, List.of("owncast"), "/bff/owncast/mod/streams").exchange()
                .expectStatus().isForbidden();
    }

    // ── PUBLIC PROBES — actuator health/info anonymous on both chains ─────────

    @Test
    void anonymous_allowedOn_actuatorProbes() {
        for (String path : List.of("/actuator/health", "/actuator/info")) {
            prod.get().uri(path).exchange().expectStatus().value(s -> assertNot401Nor403(path, s));
            dev.get().uri(path).exchange().expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    // ── PROD SPEC GATING — this repo's gap ────────────────────────────────────

    @Test
    void prod_specPaths_requireAdminOrSuperadmin() {
        // PROD chain: /v3/api-docs/** + swagger require ADMIN|SUPERADMIN. Anonymous 401,
        // a plain user 403 — the API contract is never publicly reachable in prod.
        for (String path : List.of("/v3/api-docs", "/swagger-ui.html")) {
            prod.get().uri(path).exchange().expectStatus().isUnauthorized();
            as(prod, List.of("owncast"), path).exchange().expectStatus().isForbidden();
            as(prod, List.of("admin"), path).exchange().expectStatus().isOk();
        }
    }

    @Test
    void dev_specPaths_arePublic() {
        // DEV/TEST chain: the spec + Swagger UI are permitAll so gen:fetch /
        // ng-openapi-gen can curl them with no token. Anonymous reaches them (not 401/403).
        for (String path : List.of("/v3/api-docs", "/swagger-ui.html")) {
            dev.get().uri(path).exchange().expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    /** A path reached by an ALLOWED (permitAll) request must not be 401/403. The probe
     *  controller maps every path below, so a permitAll path resolves to 200; the only
     *  failures we guard against are the security 401/403. */
    private static void assertNot401Nor403(String path, int status) {
        if (status == 401 || status == 403) {
            throw new AssertionError("expected anonymous ALLOW on " + path + " but got " + status);
        }
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200
     *  (instead of a 404 that could mask a missing security decision). */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/bff/owncast/superadmin/streams",
                "/bff/owncast/admin/grants",
                "/bff/owncast/user/stream",
                "/bff/owncast/mod/streams",
                "/bff/owncast/anything",
                "/api/whatever",
                "/actuator/health", "/actuator/info",
                "/v3/api-docs", "/swagger-ui.html",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
