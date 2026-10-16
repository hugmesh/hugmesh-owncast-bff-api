package net.hugmesh.owncastbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import net.hugmesh.commons.security.CasdoorAuthorities;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.owncastbff.security.PrincipalDomain;

/**
 * Casdoor-aware OAuth2 resource-server security for the owncast BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates the {@code @PreAuthorize}
 * gates on the controllers. The JWT→authority mapping is delegated to the shared
 * {@link CasdoorAuthorities} converter — COPIED (logic) from the
 * adversarially-verified-safe hugmesh-gateway / wiki-bff so the BFF and the gateway
 * emit BYTE-IDENTICAL authorities, including the reserved-prefix injection guard on
 * {@code permissions} and exactly one issuer-derived {@code DOMAIN_<x>} tenant
 * authority.
 *
 * <p><b>Broadcast-governance context.</b> This BFF owns the may-broadcast governance
 * plane ({@code owncast_grant}), NOT the media plane: the per-streamer Owncast
 * instances (RTMP {@code :1935} ingest tailnet-only + HLS {@code :8080} playback) are
 * SEPARATE Deployments reached on their own gateway paths. This filter chain is
 * DEFENCE IN DEPTH on top of the gateway route-access:
 * <ul>
 *   <li>{@code /bff/owncast/superadmin/**} -> {@code hasRole('SUPERADMIN')} — the
 *       MANAGE-ALL surface (OWNCAST_MANAGE: list-all + history). Declared FIRST so the
 *       most-specific prefix wins.</li>
 *   <li>{@code /bff/owncast/admin/**} -> {@code hasAnyRole('ADMIN','SUPERADMIN')} — the
 *       OWNCAST_GOVERN grant/timeout/ban/restore surface. Admins reach it via the
 *       converter's ROLE_ADMIN; SUPERADMIN reaches it via the role hierarchy edge.</li>
 *   <li>{@code /bff/owncast/mod/**} -> {@code hasAnyRole('MOD','ADMIN','SUPERADMIN')} — the
 *       MODERATION surface (list a brand's streams; hide/kill/restore a target owner;
 *       ban/restore reuse {@code owncast_grant(banned)}). Declared before the floor so the
 *       moderation prefix wins; kill/hide/ban/restore ONLY (no grant/govern path).</li>
 *   <li>{@code /bff/owncast/**} -> {@code .authenticated()} — the floor. The ROLE_OWNCAST
 *       route-access floor is enforced at the gateway; the converter adds ROLE_USER to
 *       every principal so {@code .authenticated()} proves authentication.</li>
 * </ul>
 *
 * <p><b>Default-deny broadcast.</b> Broadcast is GRANT-ONLY: there is no static role
 * that confers it (unlike wiki read's ADMIN|SUPERADMIN|(MOD AND WIKI) floor). The exact
 * decision — an active {@code owncast_grant} broadcast grant AND NOT an active ban, with
 * SUPERADMIN exempt — is enforced programmatically by {@code OwncastBroadcastGuard},
 * because a static SpEL cannot consult the DB for a per-principal grant or ban.
 *
 * <p><b>Domain-scope (multi-brand).</b> The owncast grants are per-domain. A scoped
 * ADMIN of brand X governs ONLY brand X's streamers; the service/repo layers add a
 * {@code domain = :domain} predicate derived SERVER-SIDE from the validated issuer
 * ({@link PrincipalDomain}), with SUPERADMIN unscoped.
 *
 * <p><b>Multi-issuer is OPT-IN + backward-compatible.</b> When
 * {@code app.tenancy.issuers} carries per-brand issuer=domain pairs
 * ({@link TenancyResourceServerConfig} contributes a resolver AND the registry is
 * {@link DomainRegistry#isMultiIssuer()}), each trusted per-brand Casdoor validates
 * its own tokens (unknown {@code iss} → 401). Otherwise the resource server stays on
 * the existing single {@code o.jwt(...)} issuer-uri path — byte-for-byte unchanged.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
// SecurityConfig depends on DomainRegistry (the converter stamps the issuer-derived
// DOMAIN_<x>); PrincipalDomain is the controllers'/service's single domain-resolution
// bean. Importing both here means every @WebFluxTest slice that imports SecurityConfig
// gets them too — the slice context loads without each test re-declaring them.
@Import({DomainRegistry.class, PrincipalDomain.class})
public class SecurityConfig {

    /** Issuer→domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no issuer
     *  at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider value)
     *  ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays on
     *  the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the current
     *  single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** D8 MFA floor (from the merged gateway) — {@code app.mfa.enabled}
     *  (default {@code false}: present in the code but switched off by default). When false
     *  the converter emits the legacy authority set verbatim and {@code MFA_SATISFIED} is never
     *  produced. */
    private final boolean mfaEnabled;

    /** D8 MFA freshness window {@code app.mfa.freshness-window} in millis (default
     *  10m). {@code 0 <= now - mfa_satisfied_at <= window} keeps the marker fresh. */
    private final long mfaFreshnessWindowMillis;

    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
    }

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface. {@code /v3/api-docs} is the raw
     * OpenAPI JSON the platform ng-openapi-gen typed clients (the paired
     * hugmesh-owncast-ui) + the docs pipeline fetch. Gated per profile (see the two
     * filter-chain beans): public under dev/test so {@code gen:fetch} can curl the
     * spec without a token, ROLE_ADMIN / SUPERADMIN everywhere else (prod) so the API
     * contract is never publicly reachable — matching the wiki-bff / forum-bff template.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The
     * ONLY difference between the two profiles is how {@link #SPEC_PATHS} is gated,
     * so every other route lives here to keep the two chains in lockstep and make
     * it impossible to loosen a non-spec route by editing only one chain.
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // EVERY other actuator path is an operator surface (env, beans, heapdump, metrics,
        // loggers, prometheus ...). Today the exposure list (health,info) leaves nothing
        // behind it, but an env override or a new starter widens that list with no code
        // change, and the anyExchange().authenticated() floor below would then hand it to
        // any logged-in ROLE_USER. Decide it here, first-match-wins, so it fails CLOSED
        // whatever is exposed. Explicit hasAnyRole, not the hierarchy edge.
        ex.pathMatchers("/actuator/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // The MANAGE-ALL surface — SUPERADMIN only (OWNCAST_MANAGE: list-all + history).
        // Declared BEFORE the admin + floor prefixes so the most-specific path matches first.
        ex.pathMatchers("/bff/owncast/superadmin/**").hasRole("SUPERADMIN");
        // The OWNCAST_GOVERN grant/timeout/ban/restore surface — ADMIN (or the cross-domain
        // SUPERADMIN super-role) end-to-end. Admins reach it via the converter's ROLE_ADMIN;
        // SUPERADMIN reaches it via the role hierarchy edge.
        ex.pathMatchers("/bff/owncast/admin/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // The STREAMER self-service surface (owncast_stream: get/upsert own stream, flip own
        // visibility) — the ROLE_OWNCAST base service role floor. Declared BEFORE the generic
        // /bff/owncast/** floor so this prefix is gated to ROLE_OWNCAST. OWNCAST is a SIBLING
        // role (no SUPERADMIN>OWNCAST hierarchy edge, and path matchers don't apply hierarchy
        // anyway), so a principal reaching this surface carries ROLE_OWNCAST — matching the
        // gateway route-access floor. The EXTRA rule (a PUBLIC visibility flip needs an active
        // broadcast grant, SUPERADMIN exempt) is enforced in OwncastStreamService via
        // OwncastBroadcastGuard — NOT here, because a static SpEL cannot consult the DB.
        ex.pathMatchers("/bff/owncast/user/**").hasRole("OWNCAST");
        // The MODERATION surface (owncast_moderation_audit + reused owncast_grant/owncast_stream:
        // list a brand's streams, hide/kill/restore a target owner) — MOD | ADMIN | SUPERADMIN.
        // Declared BEFORE the generic /bff/owncast/** floor so this prefix is gated to the
        // moderation roles. ADMIN and MOD are documented SIBLINGS (no ADMIN>MOD hierarchy edge,
        // and path matchers don't apply the @PreAuthorize role hierarchy anyway), so the
        // disjunction is EXPLICIT — a MOD reaches it via the converter's ROLE_MOD, an ADMIN via
        // ROLE_ADMIN, a SUPERADMIN via ROLE_SUPERADMIN; a plain USER or a bare ROLE_OWNCAST
        // streamer is denied. The moderation verbs are kill/hide/ban/restore ONLY — a MOD cannot
        // reach the admin/superadmin govern prefixes through this surface (those are separate
        // controllers under the higher path gates above), and never GRANTs broadcast. The
        // domain-scope (moderatorDomain == validated issuer, no superadmin all-brands bypass) is
        // enforced in OwncastModerationService.
        ex.pathMatchers("/bff/owncast/mod/**").hasAnyRole("MOD", "ADMIN", "SUPERADMIN");
        // The rest of the owncast surface — the ROLE_OWNCAST floor is enforced at the
        // gateway, so .authenticated() proves authentication here. The exact broadcast
        // decision (an active grant AND NOT an active ban, SUPERADMIN exempt) is enforced
        // programmatically by OwncastBroadcastGuard — NOT here, because a static SpEL
        // cannot consult the DB for a per-principal grant/ban.
        ex.pathMatchers("/bff/owncast/**").authenticated();
    }

    /**
     * Hardened HTTP response headers — the API-DEFENSIVE MINIMUM for a pure-JSON
     * resource-server BFF (OWASP secure-headers / NIST 800-228). This BFF NEVER serves
     * HTML or a document and ALWAYS sits behind the hugmesh-gateway public entry point, which
     * emits the full browser-policy set (HSTS / Permissions-Policy / the UI-shell CSP)
     * exactly once at the single TLS-terminating PEP so all brands/BFFs inherit it and
     * the 12 per-BFF configs can't drift. So this chain re-asserts ONLY defense-in-depth:
     * <ul>
     *   <li>a no-content API {@code Content-Security-Policy: default-src 'none';
     *       frame-ancestors 'none'} (a JSON body needs no resources and must never be
     *       framed);</li>
     *   <li>{@code Referrer-Policy: no-referrer} (kept explicit — also Spring's default);</li>
     *   <li>and — KEPT AS SPRING'S REACTIVE SECURE DEFAULTS, NOT disabled —
     *       {@code X-Content-Type-Options: nosniff}, {@code X-Frame-Options: DENY} and the
     *       {@code Cache-Control} no-store family.</li>
     * </ul>
     * Deliberately OMITTED here (they belong only at the gateway's TLS entry point, never on a
     * plaintext intra-mesh JSON hop): {@code Strict-Transport-Security} (meaningless over
     * HTTP) and {@code Permissions-Policy} / the UI-shell CSP (no document to govern).
     * This is purely ADDITIVE — no authz rule, issuer validation or CSRF posture changes.
     */
    private static void securityHeaders(ServerHttpSecurity.HeaderSpec h) {
        h.contentSecurityPolicy(csp -> csp.policyDirectives(
                "default-src 'none'; frame-ancestors 'none'"));
        h.referrerPolicy(rp -> rp.policy(
                ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER));
        // X-Content-Type-Options: nosniff, X-Frame-Options: DENY and the Cache-Control
        // no-store family remain Spring Security's reactive secure defaults — left
        // implicit on purpose (do NOT disable them).
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC so
     * {@code gen:fetch} (ng-openapi-gen) and the docs pipeline can curl
     * {@code /v3/api-docs} locally without a Casdoor token. Activate with
     * {@code SPRING_PROFILES_ACTIVE=dev} (or the {@code test} profile the slice
     * tests use). Every non-spec route is identical to prod.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::securityHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN (or the
     * cross-domain SUPERADMIN super-role) so the API contract is never publicly
     * reachable. Mirrors the wiki-bff / forum-bff / user-bff profile split. Every
     * non-spec route is identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::securityHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Wire the OAuth2 resource server. Multi-issuer is OPT-IN: swap to the per-issuer
     * authentication-manager resolver ONLY when BOTH a resolver was contributed by
     * {@link TenancyResourceServerConfig} AND the registry is genuinely multi-issuer
     * (more than the single back-compat entry). Gating on {@code isMultiIssuer()} —
     * not merely {@code resolver != null} — keeps a single-issuer cluster on the
     * EXISTING issuer-uri {@code o.jwt(...)} decoder path even if the tenancy
     * conditional ever activates with just the lone back-compat issuer. In true
     * multi-brand mode each trusted per-brand Casdoor validates its own tokens
     * (unknown iss -> 401, fail-closed).
     */
    private void resourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges. Deliberately MINIMAL:
     * SUPERADMIN is a strict superset of admin/mod/user, but {@code ROLE_ADMIN} and
     * {@code ROLE_MOD} are documented SIBLINGS (no {@code ADMIN > MOD} edge). This bean
     * only smooths {@code @PreAuthorize} ergonomics + lets SUPERADMIN reach the
     * admin-gated govern + spec surfaces; the actual cross-surface authorization (and
     * the domain-scope, and the default-deny broadcast decision) is enforced by the
     * service / guard layer.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    /**
     * Wire the {@link #roleHierarchy()} into REACTIVE method security so the
     * {@code @PreAuthorize("hasRole('ADMIN')")} gates honour {@code ROLE_SUPERADMIN >
     * ROLE_ADMIN} — i.e. the cross-domain SUPERADMIN reaches the ADMIN-only govern
     * methods without an explicit {@code ROLE_ADMIN}. (A bare {@code RoleHierarchy}
     * bean is NOT auto-applied to {@code @PreAuthorize} in the reactive
     * method-security path, so the expression handler is set explicitly.)
     */
    @Bean
    MethodSecurityExpressionHandler owncastMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        // Keep the default ROLE_ prefix explicit so hasRole('ADMIN') maps to ROLE_ADMIN.
        handler.setDefaultRolePrefix(new GrantedAuthorityDefaults("ROLE_").getRolePrefix());
        return handler;
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT → authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical —
     * three claim sources ({@code roles} → {@code ROLE_<UPPER>}, {@code permissions}
     * verbatim MINUS reserved-prefix injection, legacy {@code isAdmin} →
     * {@code ROLE_ADMIN}), a {@code ROLE_USER} floor, plus exactly one issuer-derived
     * {@code DOMAIN_<x>} authority (NON-role; {@code DOMAIN_default} for the
     * single-issuer fallback so this cluster is unchanged).
     */
    Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis));
    }
}
