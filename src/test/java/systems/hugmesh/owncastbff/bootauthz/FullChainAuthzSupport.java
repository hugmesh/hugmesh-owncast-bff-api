package systems.hugmesh.owncastbff.bootauthz;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.owncastbff.testsupport.TestIssuer;

import java.util.List;

/**
 * Shared scaffolding for the WAVE-2 FULL-CHAIN HTTP authz tests — the half-sibling of
 * the PR #5 {@code SecuritySliceSupport} (which builds an ISOLATED slice client around a
 * hand-constructed {@code SecurityConfig} chain + stub controllers). This support instead
 * boots the WHOLE application (a real {@code @SpringBootTest}: the production
 * {@link systems.hugmesh.owncastbff.config.SecurityConfig} filter chain + the REAL
 * controllers + the REAL services + the REAL R2DBC repositories over the H2 test DB), so
 * every assertion lands at the genuine HTTP boundary and exercises the SAME stack that
 * runs in production — including the cross-domain data-scope the slice's stub controllers
 * cannot reach.
 *
 * <p><b>Why two static {@link TestIssuer}s.</b> Authenticating a REAL RSA-signed JWT
 * through the REAL filter chain with NO live Casdoor + NO network requires the
 * multi-issuer resource-server path: the {@link TestIssuer}s stand up in-process JWKS +
 * OIDC-discovery servers on {@code 127.0.0.1}, and {@code app.tenancy.issuers} is wired to
 * the pair via {@link #issuers(DynamicPropertyRegistry)} (registered BEFORE the context
 * builds — {@code DomainRegistry} + the {@code @ConditionalOnExpression} tenancy bean read
 * it at init). Two trusted issuers make {@code DomainRegistry.isMultiIssuer()} hold, so
 * {@code SecurityConfig} swaps onto the per-brand resolver: brand-X tokens are stamped
 * {@code DOMAIN_brandx}, brand-Y tokens {@code DOMAIN_brandy}, and an unlisted issuer 401s
 * fail-closed — exactly as a real per-brand Casdoor deployment behaves.
 *
 * <p>The issuers are {@code static} (created once, never closed) so a single in-process
 * JWKS pair backs the whole class; their issuer URIs are stable for the lifetime of the
 * JVM. The same pair is the source of truth for both the property wiring and the token
 * minting.
 *
 * <p>This is TEST-ONLY support: it neither changes nor re-declares any production bean —
 * it only feeds the production {@code SecurityConfig} the multi-issuer configuration it
 * already supports and mints tokens the production decoder validates.
 */
abstract class FullChainAuthzSupport extends PostgresTestSupport {

    /** Brand-X Casdoor (in-process JWKS + OIDC discovery). Tokens it mints stamp
     *  {@code DOMAIN_brandx}. */
    static final TestIssuer BRAND_X = new TestIssuer();
    /** Brand-Y Casdoor. Tokens it mints stamp {@code DOMAIN_brandy} — the cross-domain
     *  counterpart for the DENY assertions. */
    static final TestIssuer BRAND_Y = new TestIssuer();
    /** A perfectly-signed issuer that is NOT in {@code app.tenancy.issuers} — the
     *  fail-closed 401 probe. */
    static final TestIssuer ROGUE = new TestIssuer();

    static final String DOMAIN_X = "brandx";
    static final String DOMAIN_Y = "brandy";

    @Autowired
    protected WebTestClient web;

    /**
     * Register the two trusted per-brand issuers (ROGUE is deliberately omitted so it
     * 401s). Wired as a {@code @DynamicPropertySource} so the value is present BEFORE the
     * context starts — {@code DomainRegistry} reads {@code app.tenancy.issuers} in its
     * constructor and the multi-issuer tenancy bean's {@code @ConditionalOnExpression}
     * evaluates it at context build. Each subclass re-declares the
     * {@code @DynamicPropertySource} method (JUnit requires it on the concrete test class)
     * delegating here.
     */
    static void issuers(DynamicPropertyRegistry registry) {
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=" + DOMAIN_X + "," + BRAND_Y.issuerUri() + "=" + DOMAIN_Y);
    }

    // ── request builders: a REAL bearer minted by a brand's in-process Casdoor ──────

    /** A GET to {@code path} bearing a brand-X token for {@code subject} with the given
     *  Casdoor role names. The token's {@code iss} is brand-X's, so the production chain
     *  validates it against brand-X's JWKS and stamps {@code DOMAIN_brandx}. */
    protected WebTestClient.RequestHeadersSpec<?> getX(String subject, List<String> roles, String path) {
        return web.get().uri(path).header("Authorization", "Bearer " + BRAND_X.mint(subject, roles));
    }

    protected WebTestClient.RequestHeadersSpec<?> getY(String subject, List<String> roles, String path) {
        return web.get().uri(path).header("Authorization", "Bearer " + BRAND_Y.mint(subject, roles));
    }

    protected WebTestClient.RequestBodySpec postX(String subject, List<String> roles, String path) {
        return web.post().uri(path).header("Authorization", "Bearer " + BRAND_X.mint(subject, roles));
    }

    protected WebTestClient.RequestBodySpec postY(String subject, List<String> roles, String path) {
        return web.post().uri(path).header("Authorization", "Bearer " + BRAND_Y.mint(subject, roles));
    }

    protected WebTestClient.RequestBodySpec putX(String subject, List<String> roles, String path) {
        return web.put().uri(path).header("Authorization", "Bearer " + BRAND_X.mint(subject, roles));
    }

    protected WebTestClient.RequestHeadersSpec<?> deleteX(String subject, List<String> roles, String path) {
        return web.delete().uri(path).header("Authorization", "Bearer " + BRAND_X.mint(subject, roles));
    }

    protected WebTestClient.RequestHeadersSpec<?> deleteY(String subject, List<String> roles, String path) {
        return web.delete().uri(path).header("Authorization", "Bearer " + BRAND_Y.mint(subject, roles));
    }
}
