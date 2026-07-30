package systems.hugmesh.owncastbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.config.TenancyResolvers;
import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.owncastbff.testsupport.TestIssuer;

import java.util.List;

/**
 * HARDENED-HEADER slice — proves the {@code .headers(...)} block added to BOTH
 * {@link SecurityConfig} filter chains emits the API-defensive minimum on a real
 * response, while KEEPING Spring Security's reactive secure defaults (nosniff /
 * X-Frame-Options DENY / Cache-Control) and WITHOUT disabling them. Drives the request
 * THROUGH the production filter chain (via {@link SecuritySliceSupport}), so the
 * assertions cover the actual wired behaviour, not a hand-rolled writer.
 *
 * <p>This BFF is a pure-JSON resource server that always sits behind the
 * hugmesh-gateway front door, so it deliberately does NOT emit
 * {@code Strict-Transport-Security} (meaningless over a plaintext intra-mesh hop —
 * HSTS lives only at the TLS edge) nor the UI-shell {@code Permissions-Policy} (no
 * document to govern). Those belong at the gateway.
 *
 * <p>Asserts:
 * <ul>
 *   <li><b>HEADERS PRESENT (authenticated 200)</b> — the no-content API CSP
 *       {@code default-src 'none'; frame-ancestors 'none'}, {@code Referrer-Policy:
 *       no-referrer}, and the kept Spring defaults {@code X-Content-Type-Options:
 *       nosniff} + {@code X-Frame-Options: DENY};</li>
 *   <li><b>HEADERS PRESENT on a 401</b> — the hardening also rides the fail-closed
 *       anonymous-deny response;</li>
 *   <li><b>NO HSTS</b> — {@code Strict-Transport-Security} is absent on this BFF;</li>
 *   <li><b>UNAUTHENTICATED 401</b> — an anonymous request to a gated path still 401s
 *       (the behaviour-preserving guard: header hardening did not loosen authz).</li>
 * </ul>
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private DomainRegistry registry;
    private ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver;
    private WebTestClient prod;
    private WebTestClient dev;

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

    // ── HARDENED HEADERS PRESENT on an authenticated 200 (both chains) ─────────

    @Test
    void hardenedHeaders_presentOn_authenticatedResponse_prod() {
        assertHardenedHeaders(
                as(prod, List.of("owncast"), "/bff/owncast/user/stream").exchange()
                        .expectStatus().isOk());
    }

    @Test
    void hardenedHeaders_presentOn_authenticatedResponse_dev() {
        assertHardenedHeaders(
                as(dev, List.of("owncast"), "/bff/owncast/user/stream").exchange()
                        .expectStatus().isOk());
    }

    // ── HARDENED HEADERS also ride the fail-closed 401 ─────────────────────────

    @Test
    void hardenedHeaders_presentOn_anonymous401() {
        assertHardenedHeaders(
                prod.get().uri("/bff/owncast/user/stream").exchange()
                        .expectStatus().isUnauthorized());
    }

    // ── NO HSTS on this pure-JSON intra-mesh BFF ───────────────────────────────

    @Test
    void hsts_absentOn_bff() {
        as(prod, List.of("owncast"), "/bff/owncast/user/stream").exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Strict-Transport-Security");
    }

    // ── BEHAVIOUR-PRESERVING — anonymous still 401s where expected ─────────────

    @Test
    void unauthenticated_still401s_onGatedPath() {
        // The header hardening is purely additive: an anonymous caller to a gated
        // prefix still 401s (authz floor unchanged).
        prod.get().uri("/bff/owncast/user/stream").exchange().expectStatus().isUnauthorized();
        prod.get().uri("/api/whatever").exchange().expectStatus().isUnauthorized();
    }

    /** Assert the full API-defensive header set: the no-content CSP, the explicit
     *  Referrer-Policy, and the KEPT Spring secure defaults (nosniff + X-Frame-Options). */
    private static void assertHardenedHeaders(WebTestClient.ResponseSpec resp) {
        resp.expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY");
    }

    /** Maps the gated path the slice exercises so an ALLOWED request resolves to 200. */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/bff/owncast/user/stream",
                "/api/whatever",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
