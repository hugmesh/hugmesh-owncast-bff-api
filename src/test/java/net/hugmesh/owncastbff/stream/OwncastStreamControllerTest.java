package net.hugmesh.owncastbff.stream;

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
import reactor.core.publisher.Mono;
import net.hugmesh.owncastbff.config.SecurityConfig;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.owncastbff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The streamer self-service stream surface gating + contract (reactive @WebFluxTest):
 *
 * <ul>
 *   <li>get/upsert/visibility (under /bff/owncast/user/stream/**) — ALLOWED for a ROLE_OWNCAST
 *       holder; FORBIDDEN for a principal WITHOUT ROLE_OWNCAST (a plain USER) — the path gate
 *       is the ROLE_OWNCAST floor.</li>
 *   <li>contract: get returns the caller's stream (404 when none); upsert returns the stream;
 *       visibility validates a non-blank value; a service 403 (public flip without a grant)
 *       surfaces as 403.</li>
 * </ul>
 *
 * <p>The security-critical PUBLIC-flip gate logic itself is enforced in the service and tested
 * end-to-end in {@code OwncastStreamServiceTest}; here we mock the service and assert the
 * controller wiring + the path-level ROLE_OWNCAST gate + the 403 propagation.
 */
@WebFluxTest(controllers = OwncastStreamController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class OwncastStreamControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean OwncastStreamService streams;
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

    private static OwncastStream stream(String visibility) {
        return new OwncastStream("id-1", "default", "bob", "My Show", "nightly", visibility,
                Instant.now(), Instant.now());
    }

    private static OwncastStream streamWithPlaybackUrl(String playbackUrl) {
        return stream(OwncastStream.VISIBILITY_INTERNAL).withPlaybackUrl(playbackUrl);
    }

    // ── contract (ROLE_OWNCAST) ────────────────────────────────────────
    @Test
    void getMyStream_allowedForStreamer_returnsOwnStream() {
        when(streams.getMyStream(any())).thenReturn(Mono.just(stream(OwncastStream.VISIBILITY_INTERNAL)));
        asStreamer().get().uri("/bff/owncast/user/stream")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.userSubject").isEqualTo("bob")
                .jsonPath("$.visibility").isEqualTo("internal");
    }

    /** The service resolves a non-null playbackUrl (template configured, grant active) →
     *  the DTO serialises it; the field appears in the JSON response. */
    @Test
    void getMyStream_includesPlaybackUrl_whenConfigured() {
        when(streams.getMyStream(any())).thenReturn(
                Mono.just(streamWithPlaybackUrl("/owncast/hls/index.m3u8")));
        asStreamer().get().uri("/bff/owncast/user/stream")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.playbackUrl").isEqualTo("/owncast/hls/index.m3u8");
    }

    /** The service returns null playbackUrl (template unset = dark by default, or no grant) →
     *  the field serialises as null so the UI degrades gracefully to the placeholder. */
    @Test
    void getMyStream_playbackUrlNullWhenUnconfigured() {
        when(streams.getMyStream(any())).thenReturn(
                Mono.just(stream(OwncastStream.VISIBILITY_INTERNAL)));
        asStreamer().get().uri("/bff/owncast/user/stream")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.playbackUrl").isEmpty();
    }

    @Test
    void getMyStream_404WhenNoStream() {
        when(streams.getMyStream(any())).thenReturn(Mono.empty());
        asStreamer().get().uri("/bff/owncast/user/stream")
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void upsert_allowedForStreamer_returnsStream() {
        when(streams.upsertMyStream(any(), eq("My Show"), eq("nightly")))
                .thenReturn(Mono.just(stream(OwncastStream.VISIBILITY_INTERNAL)));
        asStreamer().put().uri("/bff/owncast/user/stream").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"My Show\",\"description\":\"nightly\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.title").isEqualTo("My Show");
    }

    @Test
    void setVisibility_public_allowedForStreamerWithGrant_returnsPublic() {
        when(streams.setVisibility(any(), eq("public")))
                .thenReturn(Mono.just(stream(OwncastStream.VISIBILITY_PUBLIC)));
        asStreamer().put().uri("/bff/owncast/user/stream/visibility").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"visibility\":\"public\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.visibility").isEqualTo("public");
    }

    /** The service's 403 (a public flip without an active broadcast grant) surfaces as 403. */
    @Test
    void setVisibility_public_withoutGrant_surfaces403() {
        when(streams.setVisibility(any(), eq("public")))
                .thenReturn(Mono.error(ApiException.forbidden("broadcast requires an active grant (default-deny)")));
        asStreamer().put().uri("/bff/owncast/user/stream/visibility").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"visibility\":\"public\"}")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void setVisibility_400WhenBlank() {
        asStreamer().put().uri("/bff/owncast/user/stream/visibility").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"visibility\":\"\"}")
                .exchange().expectStatus().isBadRequest();
    }

    // ── gating (ROLE_OWNCAST floor) ────────────────────────────────────
    @Test
    void getMyStream_forbiddenForNonOwncastUser() {
        asUser().get().uri("/bff/owncast/user/stream")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void upsert_forbiddenForNonOwncastUser() {
        asUser().put().uri("/bff/owncast/user/stream").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"x\"}")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void setVisibility_forbiddenForNonOwncastUser() {
        asUser().put().uri("/bff/owncast/user/stream/visibility").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"visibility\":\"internal\"}")
                .exchange().expectStatus().isForbidden();
    }
}
