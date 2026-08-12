package net.hugmesh.owncastbff.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.owncastbff.config.SecurityConfig;
import net.hugmesh.owncastbff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The broadcast grant/timeout/ban overlay surface gating + contract (reactive @WebFluxTest):
 *
 * <ul>
 *   <li>grant/timeout/ban/restore (under /bff/owncast/admin/access/**) — ALLOWED for ADMIN +
 *       SUPERADMIN (OWNCAST_GOVERN); FORBIDDEN for a MOD+OWNCAST holder (the admin prefix is
 *       ADMIN end-to-end) and a plain USER.</li>
 *   <li>list-all/history (under /bff/owncast/superadmin/access) — ALLOWED for SUPERADMIN only
 *       (OWNCAST_MANAGE); FORBIDDEN for a plain ADMIN.</li>
 *   <li>contract: grant returns the active broadcast row; timeout validates ttlSeconds &gt; 0;
 *       restore maps an unknown accessType to 400.</li>
 * </ul>
 */
@WebFluxTest(controllers = OwncastBroadcastController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class OwncastBroadcastControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean OwncastBroadcastService access;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** Build the WebTestClient over the slice context WITH the Spring Security mock
     *  post-processor applied, so {@code mutateWith(mockJwt())} is honoured under Spring
     *  Boot 4 (the auto-configured @WebFluxTest client does not install springSecurity()). */
    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asModOwncast() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_OWNCAST")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private static OwncastGrant active(String type, Instant exp) {
        return new OwncastGrant("id-1", "default", "bob", type, OwncastGrant.STATE_ACTIVE,
                "admin-x", "reason", Instant.now(), exp, null);
    }

    // ── grant/timeout/ban/restore (OWNCAST_GOVERN) ─────────────────────
    @Test
    void grant_allowedForAdmin_returnsActiveBroadcastRow() {
        when(access.grant(eq("bob"), any(), any(), any())).thenReturn(Mono.just(active(OwncastGrant.TYPE_BROADCAST, null)));
        asAdmin().post().uri("/bff/owncast/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"reason\":\"go live\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.accessType").isEqualTo("broadcast")
                .jsonPath("$.state").isEqualTo("active");
    }

    @Test
    void ban_allowedForSuperadmin() {
        when(access.ban(eq("bob"), any(), any(), any())).thenReturn(Mono.just(active(OwncastGrant.TYPE_BANNED, null)));
        asSuperadmin().post().uri("/bff/owncast/admin/access/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.accessType").isEqualTo("banned");
    }

    @Test
    void timeout_allowedForAdmin() {
        when(access.timeout(eq("bob"), anyLong(), any(), any(), any()))
                .thenReturn(Mono.just(active(OwncastGrant.TYPE_BANNED, Instant.now().plusSeconds(3600))));
        asAdmin().post().uri("/bff/owncast/admin/access/timeout").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"ttlSeconds\":3600}")
                .exchange().expectStatus().isOk();
    }

    @Test
    void timeout_400WhenTtlNotPositive() {
        asAdmin().post().uri("/bff/owncast/admin/access/timeout").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"ttlSeconds\":0}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void grant_400WhenUserSubjectMissing() {
        asAdmin().post().uri("/bff/owncast/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void restore_allowedForAdmin() {
        when(access.revoke(eq("bob"), eq(OwncastGrant.TYPE_BANNED), any())).thenReturn(Mono.empty());
        asAdmin().delete().uri("/bff/owncast/admin/access/banned/bob")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("revoked");
    }

    @Test
    void restore_400WhenAccessTypeUnknown() {
        asAdmin().delete().uri("/bff/owncast/admin/access/bogus/bob")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void grant_forbiddenForModOwncast_governorsAreAdminsOnly() {
        asModOwncast().post().uri("/bff/owncast/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void grant_forbiddenForPlainUser() {
        asUser().post().uri("/bff/owncast/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── manage-all (OWNCAST_MANAGE) ────────────────────────────────────
    @Test
    void listActive_allowedForSuperadmin() {
        when(access.listActive(any())).thenReturn(Flux.just(active(OwncastGrant.TYPE_BROADCAST, null)));
        asSuperadmin().get().uri("/bff/owncast/superadmin/access")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.access[0].userSubject").isEqualTo("bob");
    }

    @Test
    void listActive_forbiddenForAdmin_manageIsSuperadminOnly() {
        asAdmin().get().uri("/bff/owncast/superadmin/access")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void history_allowedForSuperadmin() {
        when(access.historyFor(eq("bob"), any())).thenReturn(Flux.just(
                new OwncastGrant("id-2", "default", "bob", OwncastGrant.TYPE_BANNED, OwncastGrant.STATE_REVOKED,
                        "admin-x", "r", Instant.now(), null, Instant.now())));
        asSuperadmin().get().uri("/bff/owncast/superadmin/access/bob/history")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.access[0].state").isEqualTo("revoked");
    }
}
