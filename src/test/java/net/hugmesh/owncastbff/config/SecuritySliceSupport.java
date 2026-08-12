package net.hugmesh.owncastbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * Shared scaffolding for the owncast-BFF SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig} filter chain (the actual {@code authorizeExchange} path
 * policy + the OAuth2 resource-server wiring), with NO full Spring Boot context.
 * COPIED from the adversarially-verified-safe hugmesh-gateway
 * {@code SecuritySliceSupport}, adapted to THIS repo's {@code SecurityConfig}: its
 * constructor is identical ({@code DomainRegistry} + an {@code ObjectProvider} of the
 * optional tenant resolver), but the owncast {@code SecurityConfig} exposes TWO
 * profile-split chains — {@link SecurityConfig#filterChain(ServerHttpSecurity)} (prod;
 * {@code @Profile("!dev & !test")}) and
 * {@link SecurityConfig#devFilterChain(ServerHttpSecurity)} (dev/test) — so this
 * support exposes both {@link #sliceClient} (prod) and {@link #devSliceClient}.
 *
 * <p>This is the load-bearing half of the copyable multi-issuer pattern (see
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}): a resource-server repo replicates the
 * slice by (1) constructing its own {@code SecurityConfig} chain the same way here,
 * (2) supplying issuer-specific tokens via
 * {@link net.hugmesh.owncastbff.testsupport.TestIssuer}, and (3) asserting
 * authority emission / 401 fail-closed against {@code WebTestClient}.
 */
abstract class SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real PROD {@link SecurityConfig#filterChain(ServerHttpSecurity)} built from a
     * fresh {@link ServerHttpSecurity}. The chain is installed as a
     * {@link WebFilterChainProxy} web filter so the resource-server authentication +
     * the {@code authorizeExchange} policy (including the prod ADMIN/SUPERADMIN spec
     * gating) run exactly as in production.
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        return clientFor(chain, controllers);
    }

    /**
     * As {@link #sliceClient} but routed through the DEV/TEST chain
     * ({@link SecurityConfig#devFilterChain(ServerHttpSecurity)}), where the OpenAPI
     * spec + Swagger UI are {@code permitAll}. Used to prove the prod-vs-dev spec
     * gating difference is real (the two chains share {@code commonRoutes}, so every
     * non-spec route is identical).
     */
    static WebTestClient devSliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        SecurityWebFilterChain chain = config.devFilterChain(ServerHttpSecurity.http());
        return clientFor(chain, controllers);
    }

    private static WebTestClient clientFor(SecurityWebFilterChain chain, Object... controllers) {
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);
        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                .build();
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    @SuppressWarnings("unchecked")
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
