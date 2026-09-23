package net.hugmesh.owncastbff.bootauthz;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import net.hugmesh.owncastbff.access.OwncastGrant;
import net.hugmesh.owncastbff.access.OwncastGrantRepository;
import net.hugmesh.owncastbff.stream.OwncastStream;
import net.hugmesh.owncastbff.stream.OwncastStreamRepository;

import java.util.List;

/**
 * WAVE-2 FULL-CHAIN HTTP authorization test — the whole owncast BFF booted as a real
 * {@code @SpringBootTest} (the production {@code SecurityConfig}
 * {@link org.springframework.security.web.server.SecurityWebFilterChain} + the REAL
 * controllers + the REAL services + the REAL R2DBC repositories over a fresh
 * Liquibase-applied Testcontainers Postgres store from the shared
 * {@code net.hugmesh.commons.testsupport.PostgresTestSupport}). REAL RSA-signed JWTs are
 * minted by two in-process per-brand Casdoors ({@code TestIssuer}; no live IdP, no
 * network) and validated by the production multi-issuer resource server, so every
 * assertion is made at the genuine HTTP boundary.
 *
 * <p>This complements (does NOT duplicate) the PR #5 slices: those drive an ISOLATED
 * filter chain around STUB controllers (path-policy + decoder-wiring only); this boots
 * the WHOLE stack so the cross-domain data scope — which a stub controller cannot reach —
 * is proven END-TO-END at the HTTP layer.
 *
 * <p>Three mission areas:
 * <ol>
 *   <li><b>{@link ChainBootsAndGates}</b> — the entire filter chain boots and gates: 401
 *       anonymous on every owncast prefix; 403 for an authenticated-but-wrong-role
 *       principal.</li>
 *   <li><b>{@link CrossDomainDeny}</b> — HTTP-layer multi-brand isolation: a brand-X token
 *       can NEVER read/govern/moderate brand-Y's streams or grants. The domain is taken
 *       from the validated JWT ISSUER (never a request param/body), so brand-Y data is
 *       INVISIBLE to a brand-X moderator/admin/superadmin-scoped read.</li>
 *   <li><b>{@link RoleMatrix}</b> — who may toggle/broadcast/govern/moderate on the owncast
 *       control endpoints, end-to-end through the real {@code @PreAuthorize} +
 *       {@code authorizeExchange} path gates.</li>
 * </ol>
 *
 * <p>Categories per the comprehensive test standard: ChainBootsAndGates is
 * USER-SITUATIONAL ALLOW + CROSS-USER/role DENY; CrossDomainDeny is CROSS-USER DENY (the
 * tenant-isolation boundary, asserted in BOTH directions); RoleMatrix is the role-gated
 * ALLOW/DENY surface.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class FullChainHttpAuthzTest extends FullChainAuthzSupport {

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        issuers(registry);
    }

    // ════════════════════════════════════════════════════════════════════════
    // (1) THE WHOLE CHAIN BOOTS AND GATES — 401 anon, 403 wrong-role
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class ChainBootsAndGates {

        /** Every owncast prefix + an ungoverned path 401s an anonymous caller: the floor,
         *  each role-gated prefix, and the {@code anyExchange().authenticated()} catch-all
         *  — proving the real filter chain is installed and fail-closed. */
        @Test
        void anonymous_is401_onEveryOwncastSurface() {
            for (String path : List.of(
                    "/bff/owncast/user/stream",
                    "/bff/owncast/mod/streams",
                    "/bff/owncast/superadmin/access",
                    "/bff/owncast/anything",
                    "/api/whatever")) {
                web.get().uri(path).exchange().expectStatus().isUnauthorized();
            }
        }

        @Test
        void anonymous_is401_onWriteSurfaces() {
            web.post().uri("/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"bob\"}")
                    .exchange().expectStatus().isUnauthorized();
            web.post().uri("/bff/owncast/mod/streams/bob/ban")
                    .exchange().expectStatus().isUnauthorized();
        }

        /** A perfectly-signed token from an issuer NOT in {@code app.tenancy.issuers} gets
         *  no per-issuer manager and 401s — fail-closed, never a default-accept. Even a
         *  forged superadmin role cannot help; the token never reaches the converter. */
        @Test
        void unknownIssuerToken_is401_failClosed() {
            String rogue = ROGUE.mint("attacker", List.of("admin", "superadmin"));
            web.get().uri("/bff/owncast/superadmin/access")
                    .header("Authorization", "Bearer " + rogue)
                    .exchange().expectStatus().isUnauthorized();
        }

        @Test
        void garbageBearer_is401() {
            web.get().uri("/bff/owncast/user/stream")
                    .header("Authorization", "Bearer not-a-jwt")
                    .exchange().expectStatus().isUnauthorized();
        }

        /** A token whose signature was corrupted fails its brand's validation -> 401. */
        @Test
        void tamperedSignature_is401() {
            String t = BRAND_X.mint("user-x", List.of("admin"));
            String tampered = t.substring(0, t.length() - 4) + "AAAA";
            web.get().uri("/bff/owncast/superadmin/access")
                    .header("Authorization", "Bearer " + tampered)
                    .exchange().expectStatus().isUnauthorized();
        }

        // ── 403 wrong-role — authenticated but lacking the gate's role ──────────

        @Test
        void authenticatedPlainUser_is403_onStreamerSurface() {
            // ROLE_USER floor only (some unrelated role) -> not a streamer -> 403 on the
            // ROLE_OWNCAST-gated /bff/owncast/user/**.
            getX("plain", List.of("someotherrole"), "/bff/owncast/user/stream")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void authenticatedStreamer_is403_onModSurface() {
            // A bare ROLE_OWNCAST streamer is NOT a moderator -> 403 on /bff/owncast/mod/**.
            getX("streamer", List.of("owncast"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void authenticatedMod_is403_onAdminGovernSurface() {
            // MOD is a SIBLING of ADMIN (no edge) -> 403 on the ADMIN|SUPERADMIN govern prefix.
            postX("mod", List.of("mod"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"bob\"}")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void authenticatedAdmin_is403_onSuperadminManageSurface() {
            // /bff/owncast/superadmin/** is SUPERADMIN-only -> a plain ADMIN is 403.
            getX("admin", List.of("admin"), "/bff/owncast/superadmin/access")
                    .exchange().expectStatus().isForbidden();
        }

        /** A streamer reaches their own surface (200/404 = past the gate), proving the
         *  ALLOW side of the boot really wires the controller (not merely 403-everything).
         *  404 because this streamer has no stream row yet — the request passed the gate. */
        @Test
        void authenticatedStreamer_reachesOwnStreamSurface() {
            getX("streamer-allow", List.of("owncast"), "/bff/owncast/user/stream")
                    .exchange().expectStatus().isNotFound();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // (2) HTTP-LAYER CROSS-DOMAIN DENY — brand-X token cannot touch brand-Y
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class CrossDomainDeny {

        private OwncastStreamRepository streams;
        private OwncastGrantRepository grants;
        private org.springframework.r2dbc.core.DatabaseClient db;

        @org.springframework.beans.factory.annotation.Autowired
        void inject(OwncastStreamRepository streams, OwncastGrantRepository grants,
                    org.springframework.r2dbc.core.DatabaseClient db) {
            this.streams = streams;
            this.grants = grants;
            this.db = db;
        }

        /** Seed brand-Y data DIRECTLY in the store (bypassing HTTP) so the only variable in
         *  the assertions below is the CALLER's validated issuer. brand-Y has a streamer
         *  with a public stream and an active broadcast ban. The whole {@code @SpringBootTest}
         *  shares ONE H2 store across the class, so wipe the two tables first to keep each
         *  test independent (the {@code (domain,user_subject)} unique index would otherwise
         *  collide on the second seed). */
        @BeforeEach
        void seedBrandY() {
            db.sql("DELETE FROM owncast_grant").fetch().rowsUpdated().block();
            db.sql("DELETE FROM owncast_stream").fetch().rowsUpdated().block();
            streams.insert("ystreamer", "Y Show", "y desc",
                    OwncastStream.VISIBILITY_PUBLIC, DOMAIN_Y).block();
            grants.insertActive("ystreamer", OwncastGrant.TYPE_BANNED, null,
                    "seeded", "y-admin", DOMAIN_Y).block();
        }

        /** A brand-X MODERATOR lists streams and sees NONE of brand-Y's — the moderation
         *  list is scoped to the moderator's validated-issuer domain, so brand-Y's seeded
         *  stream is INVISIBLE. (DENY: brand-X cannot enumerate brand-Y.) */
        @Test
        void brandXMod_listStreams_doesNotSeeBrandY() {
            getX("xmod", List.of("mod"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.streams[?(@.ownerSubject=='ystreamer')]").doesNotExist();
        }

        /** The positive control: a brand-Y moderator DOES see brand-Y's stream — proving
         *  the row exists and the isolation is by validated issuer, not a blanket empty. */
        @Test
        void brandYMod_listStreams_seesBrandY() {
            getY("ymod", List.of("mod"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.streams[?(@.ownerSubject=='ystreamer')]").exists();
        }

        /** A brand-X moderator HIDING a brand-Y owner is a 404 — the target stream is in
         *  brand-Y, invisible to a brand-X-scoped write, so it cannot be forced internal.
         *  The cross-tenant action is denied at the data boundary (no rows touched). */
        @Test
        void brandXMod_hideBrandYOwner_is404_cannotReachForeignBrand() {
            postX("xmod", List.of("mod"), "/bff/owncast/mod/streams/ystreamer/hide")
                    .exchange().expectStatus().isNotFound();
            // The brand-Y stream is UNTOUCHED — a brand-Y mod still sees it public.
            getY("ymod", List.of("mod"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.streams[?(@.ownerSubject=='ystreamer' && @.visibility=='public')]")
                    .exists();
        }

        /** A brand-X moderator RESTORING a brand-Y owner is a no-op for the foreign ban:
         *  brand-Y's active ban is invisible to a brand-X-scoped restore, so it is NOT
         *  lifted. The action returns 200 (it always writes an audit row in the MOD's own
         *  brand) but the brand-Y ban survives — proven via the brand-Y mod's list. */
        @Test
        void brandXMod_restoreBrandYOwner_doesNotLiftForeignBan() {
            postX("xmod", List.of("mod"), "/bff/owncast/mod/streams/ystreamer/restore")
                    .exchange().expectStatus().isOk();
            // brand-Y's ban is STILL active (banned=true) when a brand-Y mod looks.
            getY("ymod", List.of("mod"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.streams[?(@.ownerSubject=='ystreamer' && @.banned==true)]")
                    .exists();
        }

        /** A brand-X ADMIN revoking a brand-Y broadcast/ban override touches NOTHING in
         *  brand-Y: the admin's writes are scoped to brand-X (validated issuer), so a
         *  brand-Y override is invisible and the revoke is a no-op. Returns 200 (the
         *  controller reports the desired state) but the foreign ban is unchanged. */
        @Test
        void brandXAdmin_revokeBrandYBan_isNoOp_foreignBanSurvives() {
            deleteX("xadmin", List.of("admin"), "/bff/owncast/admin/access/banned/ystreamer")
                    .exchange().expectStatus().isOk();
            // brand-Y's ban survives; a brand-Y mod still sees banned=true.
            getY("ymod", List.of("mod"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.streams[?(@.ownerSubject=='ystreamer' && @.banned==true)]")
                    .exists();
        }

        /** A brand-X SUPERADMIN's manage-all list is DOMAIN-SCOPED to brand-X here: even the
         *  cross-domain super-role, when minted by brand-X's issuer, carries
         *  {@code DOMAIN_brandx}; {@link net.hugmesh.owncastbff.security.PrincipalDomain}
         *  bypass returns null ONLY for SUPERADMIN, so {@code listActive(null)} would be
         *  cross-domain. We assert the SUPERADMIN listActive INCLUDES brand-Y (the documented
         *  superadmin cross-domain read) — the role boundary, not the tenant boundary, governs
         *  the manage surface. This fixes the EXACT current behaviour at the HTTP layer. */
        @Test
        void brandXSuperadmin_listActive_seesAllBrands_includingBrandY() {
            getX("xsuper", List.of("superadmin"), "/bff/owncast/superadmin/access")
                    .exchange().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.access[?(@.userSubject=='ystreamer' && @.domain=='" + DOMAIN_Y + "')]")
                    .exists();
        }

        /** A brand-X ADMIN's manage-all attempt is 403 (manage is SUPERADMIN-only) — so a
         *  scoped admin can never even reach the cross-domain read surface. */
        @Test
        void brandXAdmin_listActive_is403() {
            getX("xadmin", List.of("admin"), "/bff/owncast/superadmin/access")
                    .exchange().expectStatus().isForbidden();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // (3) ROLE MATRIX — who may toggle / broadcast / govern / moderate
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class RoleMatrix {

        // ── streamer self-visibility toggle (/bff/owncast/user/stream/**) ───────

        @Test
        void streamer_mayReachVisibilityToggle_butPublicNeedsGrant_403() {
            // ROLE_OWNCAST reaches the toggle (past the path gate); a PUBLIC flip without a
            // broadcast grant is the default-deny 403 from OwncastBroadcastGuard. Proves the
            // toggle endpoint is reachable AND the broadcast governance is enforced.
            putX("toggler", List.of("owncast"), "/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"public\"}")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void nonStreamer_cannotReachVisibilityToggle_403() {
            putX("notstreamer", List.of("somerole"), "/bff/owncast/user/stream/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"visibility\":\"internal\"}")
                    .exchange().expectStatus().isForbidden();
        }

        // ── broadcast govern (grant/timeout/ban/restore) — ADMIN | SUPERADMIN ───

        @Test
        void admin_mayGrantBroadcast_200() {
            postX("xadmin", List.of("admin"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"grantee-a\",\"reason\":\"go live\"}")
                    .exchange().expectStatus().isOk()
                    .expectBody().jsonPath("$.accessType").isEqualTo("broadcast")
                    .jsonPath("$.state").isEqualTo("active")
                    .jsonPath("$.domain").isEqualTo(DOMAIN_X);
        }

        @Test
        void superadmin_mayGrantBroadcast_200() {
            postX("xsuper", List.of("superadmin"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"grantee-s\"}")
                    .exchange().expectStatus().isOk()
                    .expectBody().jsonPath("$.accessType").isEqualTo("broadcast");
        }

        @Test
        void mod_mayNotGrantBroadcast_403() {
            postX("xmod", List.of("mod", "owncast"), "/bff/owncast/admin/access/grant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"bob\"}")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void plainUser_mayNotGrantBroadcast_403() {
            postX("xuser", List.of("user"), "/bff/owncast/admin/access/ban")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"bob\"}")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void admin_mayBan_andTimeout_200() {
            postX("xadmin", List.of("admin"), "/bff/owncast/admin/access/ban")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"ban-target\"}")
                    .exchange().expectStatus().isOk()
                    .expectBody().jsonPath("$.accessType").isEqualTo("banned");
            postX("xadmin", List.of("admin"), "/bff/owncast/admin/access/timeout")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"userSubject\":\"timeout-target\",\"ttlSeconds\":3600}")
                    .exchange().expectStatus().isOk()
                    .expectBody().jsonPath("$.accessType").isEqualTo("banned");
        }

        // ── manage-all (list/history) — SUPERADMIN only ─────────────────────────

        @Test
        void superadmin_mayListActive_andHistory_200() {
            getX("xsuper", List.of("superadmin"), "/bff/owncast/superadmin/access")
                    .exchange().expectStatus().isOk();
            getX("xsuper", List.of("superadmin"), "/bff/owncast/superadmin/access/bob/history")
                    .exchange().expectStatus().isOk();
        }

        @Test
        void admin_mayNotListActive_403() {
            getX("xadmin", List.of("admin"), "/bff/owncast/superadmin/access")
                    .exchange().expectStatus().isForbidden();
        }

        // ── moderation (list/hide/ban/restore) — MOD | ADMIN | SUPERADMIN ───────

        @Test
        void mod_mayListStreams_200() {
            getX("xmod", List.of("mod"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk();
        }

        @Test
        void admin_mayModerate_viaMatrix_200() {
            getX("xadmin", List.of("admin"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk();
        }

        @Test
        void superadmin_mayModerate_viaMatrix_200() {
            getX("xsuper", List.of("superadmin"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isOk();
        }

        @Test
        void streamer_mayNotModerate_403() {
            getX("xstreamer", List.of("owncast"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isForbidden();
        }

        @Test
        void plainUser_mayNotModerate_403() {
            getX("xuser", List.of("user"), "/bff/owncast/mod/streams")
                    .exchange().expectStatus().isForbidden();
        }

        /** A moderator KILL (ban+hide) of an owner that HAS a stream in the mod's brand is a
         *  200 — proving the moderation write path is reachable through the full chain for an
         *  authorized MOD. Seeds the target's stream in brand-X first (the MOD acts on it). */
        @Test
        void mod_mayBanOwnerInOwnBrand_200(
                @org.springframework.beans.factory.annotation.Autowired OwncastStreamRepository streams) {
            streams.insert("kill-target", "t", "d", OwncastStream.VISIBILITY_PUBLIC, DOMAIN_X).block();
            postX("xmod", List.of("mod"), "/bff/owncast/mod/streams/kill-target/ban")
                    .exchange().expectStatus().isOk()
                    .expectBody().jsonPath("$.action").isEqualTo("kill")
                    .jsonPath("$.banned").isEqualTo(true);
        }
    }
}
