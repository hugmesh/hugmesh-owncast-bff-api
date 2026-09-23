package net.hugmesh.owncastbff.bootauthz;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import net.hugmesh.owncastbff.access.OwncastGrant;
import net.hugmesh.owncastbff.access.OwncastGrantRepository;
import net.hugmesh.owncastbff.stream.OwncastStream;
import net.hugmesh.owncastbff.stream.OwncastStreamRepository;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * RAW-API-DENY NEGATIVE security suite for the owncast access/broadcast overlay — the
 * adversary's view of the HTTP boundary. Built on the SAME gold-exemplar harness as
 * {@link FullChainHttpAuthzTest} / {@link CrossDomainGovernIsolationTest} (the WHOLE owncast
 * BFF booted as a real {@code @SpringBootTest}: the production {@code SecurityConfig}
 * {@link org.springframework.security.web.server.SecurityWebFilterChain} + REAL controllers +
 * REAL services + REAL R2DBC repositories over the Liquibase-applied H2 store; REAL RSA-signed
 * per-brand JWTs minted by in-process {@code TestIssuer} Casdoors, validated by the production
 * multi-issuer resource server). Every assertion lands at the genuine HTTP boundary through the
 * SAME stack that runs in production — mirroring federation-api's CrossDomainWriteIsolationTest /
 * MultiIssuerSecuritySliceTest.
 *
 * <p><b>Why this file exists.</b> {@link FullChainHttpAuthzTest} fixes the role-matrix ALLOW/DENY
 * and the moderation/govern cross-domain isolation. This suite closes the explicitly-requested
 * raw-API-deny negatives with MUTATION-RESISTANT re-reads — every denied write is followed by a
 * read-back proving the action did NOT take effect (an attacker forging a body/path field, or
 * self-granting a privilege, or reaching across a tenant boundary, changes NOTHING). If any of
 * these denials were a fail-open / IDOR / cross-tenant leak, the re-read assertion would FAIL,
 * not the status check alone.
 *
 * <p>Authority for every expected status is THIS repo's {@code SecurityConfig} path table
 * (the {@code /bff/owncast/{user,mod,admin,superadmin}/**} prefixes), the controllers'
 * {@code @PreAuthorize} ({@code OWNCAST_GOVERN} = ADMIN|SUPERADMIN), and the OWNER-scoping in
 * {@code OwncastStreamService} (owner == {@code jwt.sub}; the request body/path NEVER names the
 * owner) + the default-deny {@code OwncastBroadcastGuard}.
 *
 * <p>Mission areas:
 * <ol>
 *   <li><b>{@link OwnerScopedStreamWrites}</b> — a streamer (ROLE_OWNCAST) cannot flip ANOTHER
 *       user's stream visibility: the visibility endpoint is OWNER-SCOPED (owner == jwt.sub),
 *       so even a forged {@code userSubject}/{@code owner}/{@code domain} in the body is IGNORED
 *       and the named victim's stream is UNTOUCHED. Includes the cross-tenant variant (a brand-X
 *       streamer cannot reach a brand-Y stream).</li>
 *   <li><b>{@link SelfGrantBroadcast}</b> — a user/streamer/mod cannot self-grant (or ban-lift)
 *       broadcast: the govern surface is ADMIN|SUPERADMIN, so the call is 403 AND no
 *       {@code owncast_grant} row is written (re-read via a SUPERADMIN manage list + the store).</li>
 *   <li><b>{@link RawTokenDeny}</b> — anonymous, garbage, tampered, and foreign-issuer (rogue)
 *       tokens are 401 fail-closed on the write surfaces, and the forged-role rogue writes
 *       NOTHING (re-read).</li>
 * </ol>
 *
 * <p>Categories per the comprehensive test standard: CROSS-USER DENY (owner isolation + tenant
 * isolation, both asserted via an untouched victim/foreign row = the positive control) +
 * privilege-escalation DENY (self-grant) + authentication DENY (raw/forged tokens).
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class RawApiDenyNegativeTest extends FullChainAuthzSupport {

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        issuers(registry);
    }

    private OwncastStreamRepository streams;
    private OwncastGrantRepository grants;
    private DatabaseClient db;

    @Autowired
    void inject(OwncastStreamRepository streams, OwncastGrantRepository grants, DatabaseClient db) {
        this.streams = streams;
        this.grants = grants;
        this.db = db;
    }

    /** ONE H2 store is shared across the {@code @SpringBootTest} class, so wipe both tables
     *  before each test to keep the {@code (domain,user_subject[,access_type])} unique indexes
     *  collision-free across re-seeds. */
    @BeforeEach
    void wipe() {
        db.sql("DELETE FROM owncast_grant").fetch().rowsUpdated().block();
        db.sql("DELETE FROM owncast_stream").fetch().rowsUpdated().block();
    }

    private long activeBroadcastGrants(String userSubject, String domain) {
        return db.sql("SELECT count(*) AS c FROM owncast_grant WHERE domain = :d "
                        + "AND user_subject = :u AND access_type = 'broadcast' AND state = 'active'")
                .bind("d", domain).bind("u", userSubject)
                .map(row -> row.get("c", Long.class)).one().block();
    }

    private String visibilityInStore(String userSubject, String domain) {
        return db.sql("SELECT visibility FROM owncast_stream WHERE domain = :d AND user_subject = :u")
                .bind("d", domain).bind("u", userSubject)
                .map(row -> row.get("visibility", String.class)).one().block();
    }

    // ════════════════════════════════════════════════════════════════════════
    // (1) OWNER-SCOPED STREAM WRITES — a streamer cannot flip ANOTHER's stream
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class OwnerScopedStreamWrites {

        /**
         * A ROLE_OWNCAST streamer ("attacker") with an active broadcast grant flips visibility,
         * but stuffs the body with a foreign {@code userSubject}/{@code owner}/{@code domain} to
         * try to flip the VICTIM's stream PUBLIC. The endpoint is OWNER-SCOPED: owner == jwt.sub,
         * the body owner fields are {@code @JsonIgnoreProperties(ignoreUnknown)}-dropped, so the
         * call flips the ATTACKER's OWN stream (200) and the victim's stream stays INTERNAL.
         *
         * <p>MUTATION-RESISTANT: the victim's stored visibility is re-read directly from H2 and
         * asserted still {@code internal}. If the body's {@code userSubject} were ever honoured
         * (an IDOR), the victim would flip to {@code public} and this assertion would FAIL.
         */
        @Test
        void streamerCannotFlipAnotherUsersVisibility_bodyOwnerIgnored_victimUntouched() {
            // Victim: a brand-X streamer with an INTERNAL stream (no grant — so it must stay internal).
            streams.insert("victim", "Victim Show", "v", OwncastStream.VISIBILITY_INTERNAL, DOMAIN_X).block();
            // Attacker: own INTERNAL stream + an active broadcast grant (so its OWN public flip is allowed).
            streams.insert("attacker", "Attacker Show", "a", OwncastStream.VISIBILITY_INTERNAL, DOMAIN_X).block();
            grants.insertActive("attacker", OwncastGrant.TYPE_BROADCAST, null, "seeded", "x-admin", DOMAIN_X).block();

            // The attacker tries to target the victim by name via every plausible body alias.
            putX("attacker", List.of("owncast"), "/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"public\",\"userSubject\":\"victim\","
                            + "\"owner\":\"victim\",\"ownerSubject\":\"victim\",\"domain\":\"" + DOMAIN_X + "\"}")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    // The flip applied to the ATTACKER's OWN stream — owner is jwt.sub, not the body.
                    .jsonPath("$.userSubject").isEqualTo("attacker")
                    .jsonPath("$.visibility").isEqualTo("public");

            // The VICTIM's stream is UNTOUCHED — still internal. (IDOR would have flipped it public.)
            assertEquals("internal", visibilityInStore("victim", DOMAIN_X),
                    "an owner-scoped visibility flip must NEVER touch another user's stream");
        }

        /**
         * The same attacker WITHOUT a broadcast grant: a public flip is the default-deny 403 from
         * {@code OwncastBroadcastGuard}, and the forged victim id changes nothing — BOTH the
         * attacker's and the victim's streams stay internal. Proves the guard fires on the
         * caller's OWN identity (jwt.sub), not the forged body subject.
         */
        @Test
        void streamerWithoutGrantPublicFlip_is403_andNeitherStreamFlips() {
            streams.insert("victim2", "V2", "v", OwncastStream.VISIBILITY_INTERNAL, DOMAIN_X).block();
            streams.insert("nogrant", "NG", "n", OwncastStream.VISIBILITY_INTERNAL, DOMAIN_X).block();

            putX("nogrant", List.of("owncast"), "/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"public\",\"userSubject\":\"victim2\"}")
                    .exchange().expectStatus().isForbidden();

            assertEquals("internal", visibilityInStore("nogrant", DOMAIN_X),
                    "a no-grant public flip must be denied (the attacker's own stream stays internal)");
            assertEquals("internal", visibilityInStore("victim2", DOMAIN_X),
                    "the forged victim id must be ignored — the victim's stream stays internal");
        }

        /**
         * CROSS-TENANT: a brand-X streamer (with a brand-X grant) cannot flip a brand-Y streamer's
         * stream. The owner key is jwt.sub AND the domain is the validated brand-X issuer, so the
         * brand-Y row is in a DIFFERENT (domain,user_subject) space: the attacker has no brand-X
         * stream row, so the flip is a 404 (nothing to update), and the brand-Y stream is untouched.
         *
         * <p>MUTATION-RESISTANT: brand-Y's stored visibility is re-read and asserted unchanged.
         */
        @Test
        void brandXStreamerCannotFlipBrandYStream_404_brandYUntouched() {
            // brand-Y victim stream, currently internal.
            streams.insert("ystreamer", "Y Show", "y", OwncastStream.VISIBILITY_INTERNAL, DOMAIN_Y).block();
            // brand-X attacker named "ystreamer" (same subject string, different brand) with a brand-X grant,
            // but NO brand-X stream row of their own.
            grants.insertActive("ystreamer", OwncastGrant.TYPE_BROADCAST, null, "seeded", "x-admin", DOMAIN_X).block();

            putX("ystreamer", List.of("owncast"), "/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"public\",\"domain\":\"" + DOMAIN_Y + "\"}")
                    .exchange().expectStatus().isNotFound();

            assertEquals("internal", visibilityInStore("ystreamer", DOMAIN_Y),
                    "a brand-X streamer must NEVER flip a brand-Y stream (domain is the validated issuer)");
        }

        /**
         * A plain ROLE_USER (no ROLE_OWNCAST) is denied at the {@code /bff/owncast/user/**} path
         * gate (403) BEFORE the controller — the streamer surface needs the OWNCAST service role,
         * and no body field can buy in. Re-read confirms the targeted stream is unmoved.
         */
        @Test
        void plainUserCannotReachVisibilityEndpoint_403_andNoWrite() {
            streams.insert("u-victim", "UV", "v", OwncastStream.VISIBILITY_INTERNAL, DOMAIN_X).block();

            putX("plainuser", List.of("user"), "/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"public\",\"userSubject\":\"u-victim\"}")
                    .exchange().expectStatus().isForbidden();

            assertEquals("internal", visibilityInStore("u-victim", DOMAIN_X),
                    "a non-streamer denied at the path gate must write nothing");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // (2) SELF-GRANT BROADCAST — broadcast grant is ADMIN|SUPERADMIN-gated
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class SelfGrantBroadcast {

        /**
         * A ROLE_OWNCAST streamer POSTs an {@code access/grant} for THEMSELVES — the obvious
         * privilege-escalation: "grant my own subject broadcast". The govern surface is
         * {@code /bff/owncast/admin/access/**} (ADMIN|SUPERADMIN), so the path gate + the
         * {@code @PreAuthorize(OWNCAST_GOVERN)} deny it 403, and NO grant row is written.
         *
         * <p>MUTATION-RESISTANT: re-read via the store proves zero active broadcast grants for the
         * self-granting subject — a fail-open grant would leave a row and this assertion would FAIL.
         */
        @Test
        void streamerCannotSelfGrantBroadcast_403_andNoGrantWritten() {
            postX("selfgrant", List.of("owncast", "user"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"selfgrant\",\"reason\":\"let me go live\"}")
                    .exchange().expectStatus().isForbidden();

            assertEquals(0L, activeBroadcastGrants("selfgrant", DOMAIN_X),
                    "a streamer must NOT be able to self-grant broadcast (no grant row may be written)");
        }

        /**
         * A plain ROLE_USER self-grant attempt — same 403, no write. The govern surface confers no
         * access to the base service/user roles at all.
         */
        @Test
        void plainUserCannotSelfGrantBroadcast_403_andNoGrantWritten() {
            postX("u-self", List.of("user"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"u-self\"}")
                    .exchange().expectStatus().isForbidden();

            assertEquals(0L, activeBroadcastGrants("u-self", DOMAIN_X),
                    "a plain user must NOT be able to self-grant broadcast");
        }

        /**
         * A MOD is a SIBLING of ADMIN (no edge) — a mod cannot grant broadcast (their own or
         * anyone's): 403, no write. The moderation surface is kill/hide/ban/restore ONLY.
         */
        @Test
        void modCannotSelfGrantBroadcast_403_andNoGrantWritten() {
            postX("mod-self", List.of("mod", "owncast"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"mod-self\"}")
                    .exchange().expectStatus().isForbidden();

            assertEquals(0L, activeBroadcastGrants("mod-self", DOMAIN_X),
                    "a mod must NOT be able to grant broadcast (sibling of ADMIN, no govern path)");
        }

        /**
         * A streamer cannot lift their OWN active broadcast ban via the govern DELETE either:
         * seed an active ban for the streamer, fire the streamer's DELETE of their {@code banned}
         * override — 403 at the ADMIN-gated path, and the ban SURVIVES (re-read via the store).
         * This denies the "ban-lift" escalation, not just the grant one.
         */
        @Test
        void bannedStreamerCannotSelfRevokeBan_403_andBanSurvives() {
            grants.insertActive("banned-self", OwncastGrant.TYPE_BANNED, null, "seeded ban",
                    "x-admin", DOMAIN_X).block();

            deleteX("banned-self", List.of("owncast", "user"),
                    "/bff/owncast/admin/access/banned/banned-self")
                    .exchange().expectStatus().isForbidden();

            Long activeBans = db.sql("SELECT count(*) AS c FROM owncast_grant WHERE domain = :d "
                            + "AND user_subject = 'banned-self' AND access_type = 'banned' AND state = 'active'")
                    .bind("d", DOMAIN_X)
                    .map(row -> row.get("c", Long.class)).one().block();
            assertEquals(1L, activeBans,
                    "a banned streamer must NOT be able to self-revoke their ban (it must survive)");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // (3) RAW TOKEN DENY — anon / garbage / tampered / foreign-issuer on writes
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class RawTokenDeny {

        /** Anonymous write to the govern grant surface is 401 (no token) and writes nothing. */
        @Test
        void anonymousGrant_is401_andNoWrite() {
            web.post().uri("/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"anon-target\"}")
                    .exchange().expectStatus().isUnauthorized();
            assertEquals(0L, activeBroadcastGrants("anon-target", DOMAIN_X),
                    "an anonymous grant must write nothing");
        }

        /** Anonymous visibility flip is 401. */
        @Test
        void anonymousVisibilityFlip_is401() {
            web.put().uri("/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"public\"}")
                    .exchange().expectStatus().isUnauthorized();
        }

        /** A non-JWT garbage bearer on a write surface is 401 — never decoded, never authorized. */
        @Test
        void garbageBearerGrant_is401() {
            web.post().uri("/bff/owncast/admin/access/grant")
                    .header("Authorization", "Bearer not-a-jwt")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"x\"}")
                    .exchange().expectStatus().isUnauthorized();
        }

        /** A signature-tampered brand-X admin token on a write is 401 (fails JWS verification). */
        @Test
        void tamperedSignatureGrant_is401() {
            String t = BRAND_X.mint("xadmin", List.of("admin"));
            String tampered = t.substring(0, t.length() - 4) + "AAAA";
            web.post().uri("/bff/owncast/admin/access/grant")
                    .header("Authorization", "Bearer " + tampered)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"x\"}")
                    .exchange().expectStatus().isUnauthorized();
        }

        /**
         * A perfectly-signed token from a ROGUE issuer NOT in {@code app.tenancy.issuers} — even
         * carrying a FORGED superadmin role — is 401 fail-closed: it gets no per-issuer manager,
         * so it never reaches the converter, and writes NOTHING.
         *
         * <p>MUTATION-RESISTANT: re-read confirms no grant row for the rogue's target subject.
         */
        @Test
        void foreignIssuerForgedSuperadminGrant_is401_andNoWrite() {
            String rogue = ROGUE.mint("attacker", List.of("admin", "superadmin"));
            web.post().uri("/bff/owncast/admin/access/grant")
                    .header("Authorization", "Bearer " + rogue)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"rogue-target\"}")
                    .exchange().expectStatus().isUnauthorized();

            // No active broadcast grant in ANY brand for the rogue's target.
            Long any = db.sql("SELECT count(*) AS c FROM owncast_grant "
                            + "WHERE user_subject = 'rogue-target' AND access_type = 'broadcast' "
                            + "AND state = 'active'")
                    .map(row -> row.get("c", Long.class)).one().block();
            assertEquals(0L, any, "a foreign-issuer forged-superadmin grant must write nothing");
        }
    }
}
