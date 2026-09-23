package net.hugmesh.owncastbff.bootauthz;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import net.hugmesh.owncastbff.access.OwncastGrant;
import net.hugmesh.owncastbff.access.OwncastGrantRepository;

import java.util.List;

/**
 * WAVE-2C — closing the cross-domain GOVERN isolation gap left by the WAVE-2
 * {@link FullChainHttpAuthzTest}. Same harness (the WHOLE owncast BFF booted as a real
 * {@code @SpringBootTest}: the production {@code SecurityConfig}
 * {@link org.springframework.security.web.server.SecurityWebFilterChain} + REAL controllers
 * + REAL services + REAL R2DBC repositories over the Liquibase-applied H2 store; REAL
 * RSA-signed per-brand JWTs minted by two in-process {@code TestIssuer} Casdoors validated by
 * the production multi-issuer resource server). Every assertion lands at the genuine HTTP
 * boundary through the SAME stack that runs in production.
 *
 * <p><b>Why this file exists (the gap).</b> WAVE-2's {@code CrossDomainDeny} proved the
 * cross-domain DENY for the MODERATION list/hide/restore surface and for revoking a brand-Y
 * <em>banned</em> override, and it fixed the superadmin manage-all ALLOW at
 * ({@code brandXSuperadmin_listActive_seesAllBrands_includingBrandY}). It left two gaps this
 * file closes, both as MUTATION-RESISTANT cross-domain DENY/isolation cases:
 *
 * <ol>
 *   <li><b>The GOVERN DELETE of a brand-Y BROADCAST grant.</b> WAVE-2 only revoked a brand-Y
 *       {@code banned} row; the symmetric — and more dangerous — case is a brand-X ADMIN
 *       DELETE-ing a brand-Y <em>broadcast</em> grant (taking another brand's streamer OFF
 *       air). We seed an active brand-Y broadcast grant directly, fire the brand-X admin
 *       DELETE, and assert the foreign grant <em>survives</em> (proven via a brand-Y
 *       SUPERADMIN/own-brand read). This is mutation-resistant: if {@code findActive}/{@code
 *       revoke}'s {@code domain = :domain} scope were removed, the brand-X DELETE would
 *       actually revoke the brand-Y broadcast row and the survival assertion would FAIL — so
 *       the test pins the isolation guard, not just a 200 no-op shape.</li>
 *   <li><b>A SCOPED admin cannot REACH the cross-domain manage surface — body-asserted.</b>
 *       WAVE-2 has {@code brandXAdmin_listActive_is403} (status only). Here we ALSO assert the
 *       403 carries NO body — a genuine security denial at the {@code SUPERADMIN}-only path
 *       gate that NEVER reaches the controller (so it cannot leak a brand-Y row), the exact
 *       negative counterpart to the pinned superadmin cross-domain read.</li>
 * </ol>
 *
 * <p>Categories per the comprehensive test standard: CROSS-USER DENY (the tenant-isolation
 * boundary, asserted via a surviving foreign row = the positive control) + the role boundary
 * on the manage surface.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class CrossDomainGovernIsolationTest extends FullChainAuthzSupport {

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        issuers(registry);
    }

    private OwncastGrantRepository grants;
    private DatabaseClient db;

    @Autowired
    void inject(OwncastGrantRepository grants, DatabaseClient db) {
        this.grants = grants;
        this.db = db;
    }

    /**
     * Seed a brand-Y ACTIVE BROADCAST grant DIRECTLY in the store (bypassing HTTP) so the only
     * variable in the assertions is the CALLER's validated issuer. The whole {@code
     * @SpringBootTest} shares ONE H2 store across the class, so wipe the grant table first to
     * keep each test independent (the {@code (domain,user_subject,access_type)} partial-unique
     * index would otherwise collide on a re-seed).
     */
    @BeforeEach
    void seedBrandYBroadcastGrant() {
        db.sql("DELETE FROM owncast_grant").fetch().rowsUpdated().block();
        grants.insertActive("ystreamer", OwncastGrant.TYPE_BROADCAST, null,
                "seeded brand-Y broadcast grant", "y-admin", DOMAIN_Y).block();
    }

    // ════════════════════════════════════════════════════════════════════════
    // (1) GOVERN DELETE of a brand-Y BROADCAST grant — cross-domain no-op
    // ════════════════════════════════════════════════════════════════════════

    /**
     * A brand-X ADMIN DELETE-ing a brand-Y BROADCAST grant touches NOTHING in brand-Y: the
     * admin's reads/writes are scoped to brand-X (validated issuer), so a brand-Y override is
     * invisible and the revoke resolves no row. The controller reports the desired state (200,
     * {@code state=revoked} — it is idempotent on a missing row) but the FOREIGN broadcast
     * grant is unchanged.
     *
     * <p>MUTATION-RESISTANT: the survival is proven by a brand-Y SUPERADMIN reading the grant
     * back as {@code state=active}. If {@code OwncastGrantRepository.findActive}'s {@code domain
     * = :domain} predicate (or {@code OwncastBroadcastService.revoke}'s server-derived scope)
     * were removed, the brand-X DELETE WOULD revoke the brand-Y row and this assertion would
     * FAIL — the test would not pass on a no-op guard alone.
     */
    @Test
    void brandXAdmin_deleteBrandYBroadcastGrant_isNoOp_foreignGrantSurvives() {
        deleteX("xadmin", List.of("admin"),
                "/bff/owncast/admin/access/broadcast/ystreamer")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.state").isEqualTo("revoked")
                .jsonPath("$.accessType").isEqualTo("broadcast")
                .jsonPath("$.userSubject").isEqualTo("ystreamer");

        // The brand-Y broadcast grant is STILL active — a SUPERADMIN's cross-domain manage read
        // sees the brand-Y row unchanged. (SUPERADMIN is the only role that can read another
        // brand's grant; we use it as the source-of-truth probe for the foreign row.)
        getX("xsuper", List.of("superadmin"), "/bff/owncast/superadmin/access")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.access[?(@.userSubject=='ystreamer' && @.domain=='" + DOMAIN_Y
                        + "' && @.accessType=='broadcast' && @.state=='active')]")
                .exists();
    }

    /**
     * The positive control for the no-op above: a brand-X admin DELETE of a brand-Y broadcast
     * grant must ALSO not silently revoke a brand-Y row via the data layer. We assert the row
     * survives directly in the store (the {@code @SpringBootTest} shares the H2 instance), so
     * this is independent of the HTTP read path's own scoping — a second, lower-level witness
     * that the cross-domain write reached no brand-Y row.
     */
    @Test
    void brandXAdmin_deleteBrandYBroadcastGrant_leavesBrandYRowActiveInStore() {
        deleteX("xadmin", List.of("admin"),
                "/bff/owncast/admin/access/broadcast/ystreamer")
                .exchange().expectStatus().isOk();

        Long activeBrandYBroadcastRows = db.sql(
                        "SELECT count(*) AS c FROM owncast_grant WHERE domain = :d "
                        + "AND user_subject = 'ystreamer' AND access_type = 'broadcast' "
                        + "AND state = 'active'")
                .bind("d", DOMAIN_Y)
                .map(row -> row.get("c", Long.class)).one().block();
        // Exactly the one seeded brand-Y broadcast grant remains active (it was NOT revoked).
        org.junit.jupiter.api.Assertions.assertEquals(1L, activeBrandYBroadcastRows,
                "brand-X admin DELETE must NOT revoke the brand-Y broadcast grant");
    }

    /**
     * The same brand-X admin DELETE on its OWN brand's broadcast grant DOES revoke it — the ALLOW
     * counterpart proving the DELETE path is genuinely wired (not a 200-always no-op): seed a
     * brand-X broadcast grant, revoke it, and confirm it is gone from the brand-X admin's own
     * view. This makes the cross-domain no-op above meaningful (the operation works in-brand).
     */
    @Test
    void brandXAdmin_deleteOwnBrandBroadcastGrant_actuallyRevokesIt() {
        // Seed a brand-X broadcast grant alongside the (already-seeded) brand-Y one.
        grants.insertActive("xstreamer", OwncastGrant.TYPE_BROADCAST, null,
                "brand-X grant", "x-admin", DOMAIN_X).block();

        deleteX("xadmin", List.of("admin"),
                "/bff/owncast/admin/access/broadcast/xstreamer")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("revoked");

        // A SUPERADMIN manage-all read no longer shows an ACTIVE brand-X broadcast for xstreamer.
        getX("xsuper", List.of("superadmin"), "/bff/owncast/superadmin/access")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.access[?(@.userSubject=='xstreamer' && @.domain=='" + DOMAIN_X
                        + "' && @.state=='active')]")
                .doesNotExist();
    }

    // ════════════════════════════════════════════════════════════════════════
    // (2) A SCOPED admin cannot REACH the cross-domain manage surface
    // ════════════════════════════════════════════════════════════════════════

    /**
     * A brand-X ADMIN's manage-all (list-active) attempt is 403 with NO body — the {@code
     * /bff/owncast/superadmin/**} path gate is {@code SUPERADMIN}-only, so a scoped admin is
     * denied at the filter chain BEFORE the controller runs. Asserting the EMPTY body proves it
     * is a genuine security denial that never reached {@code listActive} (so it cannot leak a
     * brand-Y grant) — the exact negative counterpart of the pinned superadmin cross-domain
     * read. This BODY assertion is the WAVE-2C tightening over WAVE-2's status-only
     * {@code brandXAdmin_listActive_is403}.
     */
    @Test
    void brandXAdmin_listActive_is403_andNoBodyLeaked() {
        getX("xadmin", List.of("admin"), "/bff/owncast/superadmin/access")
                .exchange().expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    /**
     * The brand-Y manage-all (history) surface is likewise 403 for a brand-X ADMIN — proving the
     * manage gate is role-bound, not tenant-bound: a scoped admin cannot reach the cross-domain
     * read EVEN for its own-named principal, let alone a brand-Y one. Body asserted empty (the
     * gate denies before the controller).
     */
    @Test
    void brandXAdmin_history_is403_andNoBodyLeaked() {
        getX("xadmin", List.of("admin"), "/bff/owncast/superadmin/access/ystreamer/history")
                .exchange().expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    /**
     * A brand-Y ADMIN is equally barred from the manage surface — the role boundary holds
     * regardless of brand, so neither brand's scoped admin can enumerate cross-domain grants.
     * (Symmetry probe: WAVE-2 only ever drove the manage DENY from brand-X.) Empty body.
     */
    @Test
    void brandYAdmin_listActive_is403_andNoBodyLeaked() {
        getY("yadmin", List.of("admin"), "/bff/owncast/superadmin/access")
                .exchange().expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    /**
     * The cross-domain GOVERN read DENY is also closed from the MODERATION direction — a brand-X
     * admin can moderate (list streams) but the manage-all grant ledger remains SUPERADMIN-only.
     * Here a brand-X admin that CAN reach the moderation surface (200) still CANNOT reach the
     * superadmin manage surface (403, empty) in the SAME test — pinning that the two surfaces
     * have distinct, correctly-ordered path gates.
     */
    @Test
    void brandXAdmin_reachesModerationButNotManage() {
        // ADMIN is in the MOD|ADMIN|SUPERADMIN moderation gate -> reaches the surface (200).
        getX("xadmin", List.of("admin"), "/bff/owncast/mod/streams")
                .exchange().expectStatus().isOk();
        // ...but the SUPERADMIN-only manage surface is still 403 with no leaked body.
        getX("xadmin", List.of("admin"), "/bff/owncast/superadmin/access")
                .exchange().expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    // ════════════════════════════════════════════════════════════════════════
    // (3) DELETE body-shape DENY — the controller's own 400 carries $.error
    // ════════════════════════════════════════════════════════════════════════

    /**
     * The GOVERN DELETE with an UNKNOWN accessType is a controller-level 400 carrying the
     * {@code $.error} body the UIs read — distinct from the cross-domain no-op (which is a 200
     * silent guard) and the security 403 (empty body). A brand-X admin is PAST the path gate
     * here (so this exercises the controller's own input validation, not the security boundary),
     * and the bad {@code accessType} never resolves a row in EITHER brand. We assert the brand-Y
     * broadcast grant survives, so even a malformed govern call cannot reach a foreign row.
     */
    @Test
    void brandXAdmin_deleteUnknownAccessType_is400_withErrorBody_andNoForeignWrite() {
        deleteX("xadmin", List.of("admin"),
                "/bff/owncast/admin/access/bogus/ystreamer")
                .exchange().expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("accessType must be 'broadcast' or 'banned'");

        // The seeded brand-Y broadcast grant is untouched by the rejected govern call.
        getX("xsuper", List.of("superadmin"), "/bff/owncast/superadmin/access")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.access[?(@.userSubject=='ystreamer' && @.domain=='" + DOMAIN_Y
                        + "' && @.state=='active')]")
                .exists();
    }
}
