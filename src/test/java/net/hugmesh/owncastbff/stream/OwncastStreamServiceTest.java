package net.hugmesh.owncastbff.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.test.StepVerifier;
import net.hugmesh.owncastbff.access.OwncastBroadcastGuard;
import net.hugmesh.owncastbff.access.OwncastBroadcastService;
import net.hugmesh.owncastbff.access.OwncastGrantRepository;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.owncastbff.security.PrincipalDomain;
import net.hugmesh.owncastbff.support.PostgresSliceTestConfig;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The OWNER-controlled stream service over the REAL stream repo + the REAL broadcast guard +
 * grant store + a multi-brand {@link PrincipalDomain}, so the issuer-derived owner+domain
 * scoping AND the security-critical PUBLIC-flip gate are exercised end to end. Delineated per
 * the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a streamer gets/upserts THEIR OWN stream; sets title/desc; a
 *       first upsert creates an INTERNAL stream; flips visibility internal&lt;-&gt;public.</li>
 *   <li><b>CROSS-USER (DENY isolation)</b> — streamer A cannot read or modify streamer B's
 *       stream (owner == jwt.sub; A's writes never touch B's row).</li>
 *   <li><b>SECURITY-CRITICAL GATE</b> — a user WITHOUT an active broadcast grant CANNOT set
 *       visibility=public (403) but CAN keep/set it internal; a BANNED user (even one with a
 *       grant) cannot make it public; a GRANTED user can; SUPERADMIN is exempt per the guard.</li>
 *   <li><b>DOMAIN ISOLATION</b> — a stream in brand X is not visible to brand Y; a grant in
 *       brand Y does not let the owner publish in brand X.</li>
 *   <li><b>ONE-STREAM-PER-STREAMER</b> — a re-upsert updates the SAME row (no second row).</li>
 *   <li><b>FAIL-CLOSED</b> — a non-JWT / subject-less principal is rejected (401).</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import(PostgresSliceTestConfig.class)
class OwncastStreamServiceTest extends PostgresTestSupport {

    @Autowired OwncastStreamRepository streamRepo;
    @Autowired OwncastGrantRepository grantRepo;

    private OwncastStreamService service;
    private OwncastBroadcastService broadcastAccess;

    /** Multi-brand registry: brandx + brandy issuers (so issuer -> domain scoping fires). */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final PrincipalDomain PD = new PrincipalDomain(MULTI);

    /** A CONFIGURED playback-URL template (unset by default; here it is set) so we can assert
     *  the URL is RESOLVED for a permitted viewer and WITHHELD (null) from a denied one. */
    private static final OwncastPlaybackUrlResolver PLAYBACK =
            new OwncastPlaybackUrlResolver("https://{domain}.example/owncast/{subject}/hls/stream.m3u8");

    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_Y = "https://id.brandy.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "strsvc-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        OwncastBroadcastGuard guard = new OwncastBroadcastGuard(grantRepo, PD);
        service = new OwncastStreamService(streamRepo, guard, PD, PLAYBACK);
        broadcastAccess = new OwncastBroadcastService(grantRepo, PD);
    }

    /** A JWT-principal Authentication for a brand (issuer) + subject + Casdoor roles. */
    private static Authentication principal(String issuer, String subject, String... roles) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).claim("iss", issuer).issuer(issuer)
                .claim("roles", List.of(roles)).build();
        List<GrantedAuthority> auths = new ArrayList<>();
        auths.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) auths.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()));
        return new UsernamePasswordAuthenticationToken(jwt, "n/a", auths);
    }

    private static Authentication streamer(String issuer, String subject) {
        return principal(issuer, subject, "owncast");
    }

    private static void assertForbidden(reactor.core.publisher.Mono<?> m) {
        StepVerifier.create(m)
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void upsert_firstTime_createsInternalStream_ownerAndBrandServerDerived() {
            String u = user("us-first");
            Authentication streamer = streamer(ISS_X, u);

            OwncastStream s = service.upsertMyStream(streamer, "My Show", "nightly").block();
            assertThat(s.userSubject()).isEqualTo(u);        // owner == jwt.sub
            assertThat(s.domain()).isEqualTo("brandx");      // brand from issuer
            assertThat(s.title()).isEqualTo("My Show");
            assertThat(s.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL); // fail-closed default
        }

        @Test
        void getMyStream_returnsTheCallersOwnStream() {
            String u = user("us-get");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();

            OwncastStream got = service.getMyStream(streamer).block();
            assertThat(got.userSubject()).isEqualTo(u);
            assertThat(got.title()).isEqualTo("t");
        }

        @Test
        void getMyStream_empty_whenNoStreamYet() {
            assertThat(service.getMyStream(streamer(ISS_X, user("us-empty"))).blockOptional()).isEmpty();
        }

        @Test
        void upsert_setsTitleAndDescription_onExisting() {
            String u = user("us-edit");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "old", "olddesc").block();

            OwncastStream s = service.upsertMyStream(streamer, "new", "newdesc").block();
            assertThat(s.title()).isEqualTo("new");
            assertThat(s.description()).isEqualTo("newdesc");
        }

        @Test
        void setVisibility_internal_alwaysAllowed_noGrantNeeded() {
            String u = user("us-internal");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();

            // No broadcast grant — internal is still allowed.
            OwncastStream s = service.setVisibility(streamer, "internal").block();
            assertThat(s.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }

        @Test
        void setVisibility_unknownValue_isBadRequest() {
            String u = user("us-bad");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();
            StepVerifier.create(service.setVisibility(streamer, "semi-public"))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400))
                    .verify();
        }

        @Test
        void setVisibility_noStream_isNotFound() {
            // A granted streamer with no stream yet -> 404 (gate passes, but there's nothing to flip).
            String u = user("us-404");
            Authentication streamer = streamer(ISS_X, u);
            broadcastAccess.grant(u, "ok", null, principal(ISS_X, "admin-x", "admin")).block();
            StepVerifier.create(service.setVisibility(streamer, "public"))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                    .verify();
        }
    }

    // ── ONE-STREAM-PER-STREAMER ──────────────────────────────────────────────
    @Nested
    class OneStreamPerStreamer {

        @Test
        void reUpsert_updatesSameRow_noSecondStream() {
            String u = user("one-up");
            Authentication streamer = streamer(ISS_X, u);
            OwncastStream first = service.upsertMyStream(streamer, "a", "a").block();
            OwncastStream second = service.upsertMyStream(streamer, "b", "b").block();
            assertThat(second.id()).isEqualTo(first.id());      // same row, not a 2nd stream
            assertThat(second.title()).isEqualTo("b");
        }
    }

    // ── CROSS-USER (DENY isolation) ───────────────────────────────────────────
    @Nested
    class CrossUser {

        /** Streamer A cannot READ streamer B's stream — getMyStream is owner-scoped. */
        @Test
        void aCannotReadBsStream() {
            String a = user("cu-a");
            String b = user("cu-b");
            service.upsertMyStream(streamer(ISS_X, a), "a-show", null).block();
            service.upsertMyStream(streamer(ISS_X, b), "b-show", null).block();

            assertThat(service.getMyStream(streamer(ISS_X, a)).block().title()).isEqualTo("a-show");
            assertThat(service.getMyStream(streamer(ISS_X, b)).block().title()).isEqualTo("b-show");
        }

        /** Streamer A's upsert/visibility writes NEVER touch streamer B's stream. */
        @Test
        void aCannotModifyBsStream() {
            String a = user("cu-ma");
            String b = user("cu-mb");
            Authentication sa = streamer(ISS_X, a);
            Authentication sb = streamer(ISS_X, b);
            service.upsertMyStream(sa, "a", "a").block();
            service.upsertMyStream(sb, "b", "b").block();

            // A edits its own title; B is untouched.
            service.upsertMyStream(sa, "a-edited", "a2").block();
            assertThat(service.getMyStream(sb).block().title()).isEqualTo("b");
            // A flips its own visibility (after a grant); B is untouched.
            broadcastAccess.grant(a, "ok", null, principal(ISS_X, "admin-x", "admin")).block();
            service.setVisibility(sa, "public").block();
            assertThat(service.getMyStream(sb).block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }
    }

    // ── SECURITY-CRITICAL GATE (public flip needs an active broadcast grant) ──
    @Nested
    class PublicVisibilityGate {

        /** A user WITHOUT an active broadcast grant CANNOT set visibility=public (403) — the
         *  rule the rest of this PR depends on. */
        @Test
        void withoutGrant_cannotGoPublic_butCanStayInternal() {
            String u = user("gate-nogrant");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();

            assertForbidden(service.setVisibility(streamer, "public"));   // DENIED — default-deny
            // The stream is still internal (the denied flip did not write).
            assertThat(service.getMyStream(streamer).block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            // Internal is fine without a grant.
            assertThat(service.setVisibility(streamer, "internal").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }

        /** WITH an active broadcast grant, the owner CAN make their stream public. */
        @Test
        void withGrant_canGoPublic() {
            String u = user("gate-granted");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();
            broadcastAccess.grant(u, "go live", null, principal(ISS_X, "admin-x", "admin")).block();

            OwncastStream s = service.setVisibility(streamer, "public").block();
            assertThat(s.visibility()).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
        }

        /** Revoking the grant means a subsequent public flip is denied again (default-deny),
         *  though an already-public stream stays as-is until flipped. */
        @Test
        void afterGrantRevoked_publicFlipDeniedAgain() {
            String u = user("gate-revoked");
            Authentication streamer = streamer(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.upsertMyStream(streamer, "t", "d").block();
            broadcastAccess.grant(u, null, null, adminX).block();
            service.setVisibility(streamer, "public").block();      // allowed while granted

            broadcastAccess.revoke(u, net.hugmesh.owncastbff.access.OwncastGrant.TYPE_BROADCAST, adminX).block();
            // Flip back to internal (always allowed), then a re-publish is now denied.
            service.setVisibility(streamer, "internal").block();
            assertForbidden(service.setVisibility(streamer, "public"));
        }

        /** A BANNED user (even WITH a broadcast grant) cannot make their stream public — ban>grant
         *  in the guard. */
        @Test
        void bannedUser_cannotGoPublic_evenWithGrant() {
            String u = user("gate-banned");
            Authentication streamer = streamer(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.upsertMyStream(streamer, "t", "d").block();
            broadcastAccess.grant(u, "granted", null, adminX).block();
            broadcastAccess.ban(u, "abuse", null, adminX).block();        // ban>grant

            assertForbidden(service.setVisibility(streamer, "public"));
            // Still internal.
            assertThat(service.getMyStream(streamer).block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }

        /** SUPERADMIN is exempt per the guard — may make a stream public WITHOUT a broadcast grant. */
        @Test
        void superadmin_canGoPublic_withoutGrant() {
            String u = user("gate-su");
            Authentication su = principal(ISS_X, u, "owncast", "superadmin");
            service.upsertMyStream(su, "t", "d").block();

            OwncastStream s = service.setVisibility(su, "public").block();
            assertThat(s.visibility()).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
        }
    }

    // ── PLAYBACK-URL VIEW GATE (no URL leak to a non-permitted caller) ────────
    @Nested
    class PlaybackUrlViewGate {

        /** A streamer WITHOUT an active broadcast grant reads their stream metadata but gets a
         *  NULL playbackUrl — the media endpoint is NOT leaked to a non-permitted caller. */
        @Test
        void withoutGrant_playbackUrlIsNull() {
            String u = user("pb-nogrant");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();

            OwncastStream got = service.getMyStream(streamer).block();
            assertThat(got.userSubject()).isEqualTo(u);     // metadata still returned
            assertThat(got.playbackUrl()).isNull();         // URL withheld (gate denied)
        }

        /** A BANNED streamer (even WITH a grant) gets a NULL playbackUrl — ban>grant. */
        @Test
        void bannedUser_playbackUrlIsNull_evenWithGrant() {
            String u = user("pb-banned");
            Authentication streamer = streamer(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.upsertMyStream(streamer, "t", "d").block();
            broadcastAccess.grant(u, "granted", null, adminX).block();
            broadcastAccess.ban(u, "abuse", null, adminX).block();

            assertThat(service.getMyStream(streamer).block().playbackUrl()).isNull();
        }

        /** A streamer WITH an active broadcast grant is permitted to view — the playbackUrl is
         *  RESOLVED from the template for their OWN brand + subject. */
        @Test
        void withGrant_playbackUrlIsResolved() {
            String u = user("pb-granted");
            Authentication streamer = streamer(ISS_X, u);
            service.upsertMyStream(streamer, "t", "d").block();
            broadcastAccess.grant(u, "go live", null, principal(ISS_X, "admin-x", "admin")).block();

            OwncastStream got = service.getMyStream(streamer).block();
            assertThat(got.playbackUrl())
                    .isEqualTo("https://brandx.example/owncast/" + u + "/hls/stream.m3u8");
        }

        /** SUPERADMIN is exempt per the guard — permitted to view WITHOUT a grant, so the URL
         *  is resolved. */
        @Test
        void superadmin_playbackUrlIsResolved_withoutGrant() {
            String u = user("pb-su");
            Authentication su = principal(ISS_X, u, "owncast", "superadmin");
            OwncastStream created = service.upsertMyStream(su, "t", "d").block();
            // SUPERADMIN is unscoped -> the row is stored in the platform default domain;
            // the resolver uses the stream's OWN brand, so assert on that (not brandx).
            assertThat(service.getMyStream(su).block().playbackUrl())
                    .isEqualTo("https://" + created.domain() + ".example/owncast/" + u + "/hls/stream.m3u8");
        }

        /** With NO template configured (the default) the URL is null EVEN for a permitted
         *  viewer — additive + opt-in. */
        @Test
        void darkByDefault_noTemplate_playbackUrlIsNull_evenWhenPermitted() {
            OwncastStreamService darkService = new OwncastStreamService(
                    streamRepo, new OwncastBroadcastGuard(grantRepo, PD), PD,
                    new OwncastPlaybackUrlResolver(""));
            String u = user("pb-dark");
            Authentication streamer = streamer(ISS_X, u);
            darkService.upsertMyStream(streamer, "t", "d").block();
            broadcastAccess.grant(u, "go live", null, principal(ISS_X, "admin-x", "admin")).block();

            assertThat(darkService.getMyStream(streamer).block().playbackUrl()).isNull();
        }
    }

    // ── DOMAIN ISOLATION ──────────────────────────────────────────────────────
    @Nested
    class DomainIsolation {

        /** A stream in brand X is not visible to the same subject acting in brand Y. */
        @Test
        void streamInBrandX_notVisibleInBrandY() {
            String u = user("di-iso");
            service.upsertMyStream(streamer(ISS_X, u), "x-show", null).block();
            assertThat(service.getMyStream(streamer(ISS_X, u)).block().title()).isEqualTo("x-show");
            assertThat(service.getMyStream(streamer(ISS_Y, u)).blockOptional()).isEmpty();
        }

        /** A broadcast grant in brand Y does NOT let the owner publish their brand-X stream
         *  (the guard reads the owner's grants in the ACTING brand only). */
        @Test
        void grantInBrandY_doesNotLetOwnerPublishInBrandX() {
            String u = user("di-grant");
            Authentication streamerX = streamer(ISS_X, u);
            service.upsertMyStream(streamerX, "x", null).block();
            // Grant in brand Y only.
            broadcastAccess.grant(u, "y-grant", null, principal(ISS_Y, "admin-y", "admin")).block();

            // The brand-X publish is still denied (no grant in brand X).
            assertForbidden(service.setVisibility(streamerX, "public"));
        }
    }

    // ── FAIL-CLOSED (no resolvable owner) ─────────────────────────────────────
    @Nested
    class FailClosed {

        /** A non-JWT principal cannot be resolved to an owner — rejected (401). */
        @Test
        void nonJwtPrincipal_isUnauthorized() {
            Authentication noJwt = new UsernamePasswordAuthenticationToken(
                    "not-a-jwt", "n/a", List.of(new SimpleGrantedAuthority("ROLE_OWNCAST")));
            StepVerifier.create(service.getMyStream(noJwt))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(401))
                    .verify();
        }
    }
}
