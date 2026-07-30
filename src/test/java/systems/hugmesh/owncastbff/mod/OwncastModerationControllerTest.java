package systems.hugmesh.owncastbff.mod;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.owncastbff.config.SecurityConfig;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.owncastbff.web.ApiExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The MODERATION surface gating + contract + PRIVILEGE BOUNDARY (reactive @WebFluxTest):
 *
 * <ul>
 *   <li><b>ROLE GATING</b> — list/hide/ban/restore (under /bff/owncast/mod/**) are ALLOWED for a
 *       MOD, an ADMIN, and a SUPERADMIN; FORBIDDEN for a plain USER and for a bare ROLE_OWNCAST
 *       streamer (the path gate is MOD|ADMIN|SUPERADMIN — a streamer is NOT a moderator).</li>
 *   <li><b>PRIVILEGE BOUNDARY</b> — this controller exposes NO grant/govern path: there is no
 *       grant endpoint here, and a MOD hitting the admin govern prefix (/bff/owncast/admin/**)
 *       through the same client is FORBIDDEN (the admin prefix is ADMIN|SUPERADMIN). A MOD is
 *       confined to kill/hide/ban/restore.</li>
 *   <li><b>CONTRACT</b> — list returns the brand's stream rows; hide/ban/restore return the
 *       action result; a service 404 (no such stream) surfaces as 404; a service 401 (non-JWT)
 *       surfaces as 401.</li>
 * </ul>
 *
 * <p>The domain-scope + the owncast_grant reuse + the ban>grant precedence are enforced in the
 * service and tested end-to-end in {@code OwncastModerationServiceTest}; here we mock the service
 * and assert the controller wiring + the path-level role gate + the privilege boundary.
 */
@WebFluxTest(controllers = OwncastModerationController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class OwncastModerationControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean OwncastModerationService moderation;
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

    private WebTestClient asStreamer() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_OWNCAST")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private static OwncastModerationDto.ActionResult result(String action, String vis, boolean banned) {
        return new OwncastModerationDto.ActionResult(action, "bob", "brandx", vis, banned);
    }

    // ── ROLE GATING: list (MOD|ADMIN|SUPERADMIN allowed) ───────────────
    @Test
    void list_allowedForMod_returnsStreamRows() {
        when(moderation.listStreams(any())).thenReturn(Flux.just(
                new OwncastModerationDto.StreamRow("bob", "brandx", "My Show", "internal", false)));
        asMod().get().uri("/bff/owncast/mod/streams")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.streams[0].ownerSubject").isEqualTo("bob")
                .jsonPath("$.streams[0].banned").isEqualTo(false);
    }

    @Test
    void list_allowedForAdmin() {
        when(moderation.listStreams(any())).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/owncast/mod/streams").exchange().expectStatus().isOk();
    }

    @Test
    void list_allowedForSuperadmin() {
        when(moderation.listStreams(any())).thenReturn(Flux.empty());
        asSuperadmin().get().uri("/bff/owncast/mod/streams").exchange().expectStatus().isOk();
    }

    // ── ROLE GATING: DENY plain USER + bare OWNCAST streamer ───────────
    @Test
    void list_forbiddenForPlainUser() {
        asUser().get().uri("/bff/owncast/mod/streams").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_forbiddenForBareOwncastStreamer() {
        // A ROLE_OWNCAST streamer is NOT a moderator — denied the moderation surface.
        asStreamer().get().uri("/bff/owncast/mod/streams").exchange().expectStatus().isForbidden();
    }

    @Test
    void hide_forbiddenForBareOwncastStreamer() {
        asStreamer().post().uri("/bff/owncast/mod/streams/bob/hide").exchange().expectStatus().isForbidden();
    }

    @Test
    void ban_forbiddenForPlainUser() {
        asUser().post().uri("/bff/owncast/mod/streams/bob/ban").exchange().expectStatus().isForbidden();
    }

    @Test
    void restore_forbiddenForBareOwncastStreamer() {
        asStreamer().post().uri("/bff/owncast/mod/streams/bob/restore").exchange().expectStatus().isForbidden();
    }

    // ── CONTRACT: hide / ban / restore ─────────────────────────────────
    @Test
    void hide_allowedForMod_returnsInternalResult() {
        when(moderation.hide(any(), eq("bob"), any()))
                .thenReturn(Mono.just(result("hide", "internal", false)));
        asMod().post().uri("/bff/owncast/mod/streams/bob/hide")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.action").isEqualTo("hide")
                .jsonPath("$.visibility").isEqualTo("internal");
    }

    @Test
    void ban_allowedForMod_returnsBannedResult() {
        when(moderation.ban(any(), eq("bob"), any()))
                .thenReturn(Mono.just(result("kill", "internal", true)));
        asMod().post().uri("/bff/owncast/mod/streams/bob/ban")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.action").isEqualTo("kill")
                .jsonPath("$.banned").isEqualTo(true);
    }

    @Test
    void restore_allowedForMod_returnsRestoreResult() {
        when(moderation.restore(any(), eq("bob"), any()))
                .thenReturn(Mono.just(result("restore", "internal", false)));
        asMod().post().uri("/bff/owncast/mod/streams/bob/restore")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.action").isEqualTo("restore")
                .jsonPath("$.banned").isEqualTo(false);
    }

    @Test
    void hide_404WhenNoStream_surfacesServiceNotFound() {
        when(moderation.hide(any(), eq("nobody"), any()))
                .thenReturn(Mono.error(ApiException.notFound("no stream for this owner in this brand")));
        asMod().post().uri("/bff/owncast/mod/streams/nobody/hide")
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void ban_401WhenNonJwt_surfacesServiceUnauthorized() {
        when(moderation.ban(any(), eq("bob"), any()))
                .thenReturn(Mono.error(ApiException.unauthorized("an authenticated moderator subject is required")));
        asMod().post().uri("/bff/owncast/mod/streams/bob/ban")
                .exchange().expectStatus().isUnauthorized();
    }

    // ── PRIVILEGE BOUNDARY (a MOD cannot reach the admin/govern grant surface) ──
    /** The moderation controller exposes NO grant path — a MOD hitting the ADMIN govern grant
     *  endpoint (a DIFFERENT prefix) is FORBIDDEN by the path gate. This proves a MOD cannot
     *  escalate to GRANT broadcast through the owncast surface. */
    @Test
    void mod_cannotReachAdminGrantSurface() {
        asMod().post().uri("/bff/owncast/admin/access/grant")
                .header("Content-Type", "application/json")
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isForbidden();
    }

    /** A MOD cannot reach the SUPERADMIN manage-all surface either. */
    @Test
    void mod_cannotReachSuperadminSurface() {
        asMod().get().uri("/bff/owncast/superadmin/access")
                .exchange().expectStatus().isForbidden();
    }
}
