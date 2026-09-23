package net.hugmesh.owncastbff.mod;

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
import net.hugmesh.owncastbff.access.OwncastGrant;
import net.hugmesh.owncastbff.access.OwncastGrantRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.owncastbff.security.PrincipalDomain;
import net.hugmesh.owncastbff.stream.OwncastStream;
import net.hugmesh.owncastbff.stream.OwncastStreamRepository;
import net.hugmesh.owncastbff.stream.OwncastStreamService;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.owncastbff.support.PostgresSliceTestConfig;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The MODERATION service over the REAL stream repo + the REAL grant store + the REAL audit store
 * + the REAL broadcast guard + a multi-brand {@link PrincipalDomain}, so the issuer-derived
 * moderator-domain scoping, the owncast_grant REUSE (ban>grant precedence via the EXISTING
 * guard), the hide/kill/restore semantics, and the audit journal are all exercised end to end.
 * Delineated per the test standard:
 *
 * <ul>
 *   <li><b>CROSS-DOMAIN ISOLATION</b> — a mod in brand X CANNOT list/hide/ban/restore a
 *       stream/owner in brand Y (empty/no-op; never touches Y). The same owner streaming in
 *       both brands is independently moderated per brand.</li>
 *   <li><b>BAN REUSES owncast_grant + the EXISTING guard then denies</b> — a kill/ban writes an
 *       active owncast_grant(banned); the existing OwncastBroadcastGuard (ban>grant) then blocks
 *       a previously-GRANTED owner's public flip.</li>
 *   <li><b>HIDE forces internal</b>; <b>KILL = ban + hide</b>.</li>
 *   <li><b>RESTORE CAS active->revoked</b> (the ban row is RETAINED, never deleted) and does NOT
 *       auto-republish (the stream stays internal).</li>
 *   <li><b>AUDIT</b> — every action writes one owncast_moderation_audit row.</li>
 *   <li><b>FAIL-CLOSED</b> — a non-JWT / subject-less principal is rejected (401).</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import(PostgresSliceTestConfig.class)
class OwncastModerationServiceTest extends PostgresTestSupport {

    @Autowired OwncastStreamRepository streamRepo;
    @Autowired OwncastGrantRepository grantRepo;
    @Autowired OwncastModerationAuditRepository auditRepo;

    private OwncastModerationService service;
    private OwncastStreamService streamService;       // owner-side helper to set up streams
    private OwncastBroadcastService broadcastAccess;  // admin-side helper to grant/ban
    private OwncastBroadcastGuard guard;

    /** Multi-brand registry: brandx + brandy issuers (so issuer -> domain scoping fires). */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final PrincipalDomain PD = new PrincipalDomain(MULTI);

    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_Y = "https://id.brandy.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "modsvc-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        guard = new OwncastBroadcastGuard(grantRepo, PD);
        streamService = new OwncastStreamService(streamRepo, guard, PD,
                new net.hugmesh.owncastbff.stream.OwncastPlaybackUrlResolver(""));
        broadcastAccess = new OwncastBroadcastService(grantRepo, PD);
        service = new OwncastModerationService(streamRepo, grantRepo, auditRepo, PD);
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

    private static Authentication mod(String issuer, String subject) {
        return principal(issuer, subject, "mod");
    }

    private static Authentication admin(String issuer, String subject) {
        return principal(issuer, subject, "admin");
    }

    private static void assertForbidden(reactor.core.publisher.Mono<?> m) {
        StepVerifier.create(m)
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
    }

    /** Create an owner's stream in a brand and (optionally) grant + publish it. */
    private void seedPublicStream(String issuer, String owner) {
        Authentication s = streamer(issuer, owner);
        streamService.upsertMyStream(s, "show", "d").block();
        // Grant + flip public via the owner service so the public state is real.
        broadcastAccess.grant(owner, "ok", null, admin(issuer, "admin-" + issuer)).block();
        streamService.setVisibility(s, "public").block();
    }

    private boolean activeBan(String owner, String domain) {
        return grantRepo.findActive(owner, OwncastGrant.TYPE_BANNED, domain).blockOptional().isPresent();
    }

    private String visibility(String owner, String domain) {
        return streamRepo.findForOwner(owner, domain).block().visibility();
    }

    // ── LIST (domain-scoped; banned flag) ─────────────────────────────────────
    @Nested
    class ListStreams {

        @Test
        void listsOnlyTheModeratorsBrandStreams_withBannedFlag() {
            String inX = user("list-x");
            String inY = user("list-y");
            streamService.upsertMyStream(streamer(ISS_X, inX), "x-show", null).block();
            streamService.upsertMyStream(streamer(ISS_Y, inY), "y-show", null).block();
            // Ban the brand-X owner so the flag is exercised.
            broadcastAccess.ban(inX, "abuse", null, admin(ISS_X, "admin-x")).block();

            List<OwncastModerationDto.StreamRow> rows =
                    service.listStreams(mod(ISS_X, "mod-x")).collectList().block();

            // Only brand-X streams (the brand-Y stream is invisible to the brand-X moderator).
            assertThat(rows).extracting(OwncastModerationDto.StreamRow::ownerSubject).contains(inX);
            assertThat(rows).extracting(OwncastModerationDto.StreamRow::ownerSubject).doesNotContain(inY);
            assertThat(rows).allSatisfy(r -> assertThat(r.domain()).isEqualTo("brandx"));
            // The banned brand-X owner is flagged banned.
            assertThat(rows).filteredOn(r -> r.ownerSubject().equals(inX))
                    .allSatisfy(r -> assertThat(r.banned()).isTrue());
        }
    }

    // ── HIDE (force internal; moderator-initiated, NOT ownership) ─────────────
    @Nested
    class Hide {

        @Test
        void hide_forcesTargetStreamInternal_writesAudit() {
            String owner = user("hide-owner");
            seedPublicStream(ISS_X, owner);
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);

            OwncastModerationDto.ActionResult r =
                    service.hide(mod(ISS_X, "mod-x"), owner, "off-topic").block();

            assertThat(r.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            // Audit row written.
            assertThat(auditRepo.historyFor(owner, "brandx").collectList().block())
                    .filteredOn(a -> a.action().equals(OwncastModerationAudit.ACTION_HIDE))
                    .hasSize(1);
        }

        @Test
        void hide_noStream_isNotFound() {
            StepVerifier.create(service.hide(mod(ISS_X, "mod-x"), user("hide-none"), null))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                    .verify();
        }
    }

    // ── KILL/BAN (reuse owncast_grant; EXISTING guard then denies) ────────────
    @Nested
    class KillBan {

        /** A kill writes owncast_grant(banned) active AND forces the stream internal. */
        @Test
        void kill_bansViaOwncastGrant_andHides_writesAudit() {
            String owner = user("kill-owner");
            seedPublicStream(ISS_X, owner);
            assertThat(activeBan(owner, "brandx")).isFalse();

            OwncastModerationDto.ActionResult r =
                    service.ban(mod(ISS_X, "mod-x"), owner, "abuse").block();

            assertThat(r.banned()).isTrue();
            assertThat(r.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            // The ban is a REUSED owncast_grant(banned) active row (NOT a parallel mechanism).
            assertThat(activeBan(owner, "brandx")).isTrue();
            // And the stream was forced internal.
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            // Audit kill row.
            assertThat(auditRepo.historyFor(owner, "brandx").collectList().block())
                    .filteredOn(a -> a.action().equals(OwncastModerationAudit.ACTION_KILL))
                    .hasSize(1);
        }

        /** The EXISTING OwncastBroadcastGuard (ban>grant) blocks a previously-GRANTED owner's
         *  public flip AFTER a mod ban — the load-bearing precedence assertion. */
        @Test
        void afterModBan_existingGuardDeniesPreviouslyGrantedOwnersPublicFlip() {
            String owner = user("kill-grant");
            Authentication streamer = streamer(ISS_X, owner);
            // The owner is GRANTED and live (public) before the mod acts.
            streamService.upsertMyStream(streamer, "show", null).block();
            broadcastAccess.grant(owner, "go live", null, admin(ISS_X, "admin-x")).block();
            streamService.setVisibility(streamer, "public").block();
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);

            // A MOD kills the stream.
            service.ban(mod(ISS_X, "mod-x"), owner, "abuse").block();

            // Now the owner (still holding their grant) tries to go public again -> DENIED by the
            // EXISTING guard (ban>grant). The stream stays internal.
            assertForbidden(streamService.setVisibility(streamer, "public"));
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }

        /** A re-kill while already banned is idempotent — no second active ban row. */
        @Test
        void kill_idempotent_onAlreadyBanned() {
            String owner = user("kill-idem");
            seedPublicStream(ISS_X, owner);
            service.ban(mod(ISS_X, "mod-x"), owner, "first").block();
            service.ban(mod(ISS_X, "mod-x"), owner, "again").block();
            // Exactly one ACTIVE ban (idempotent); the audit has two kill rows (each action logged).
            long activeBans = grantRepo.historyFor(owner, "brandx").collectList().block().stream()
                    .filter(g -> g.accessType().equals(OwncastGrant.TYPE_BANNED) && g.isActive())
                    .count();
            assertThat(activeBans).isEqualTo(1L);
        }
    }

    // ── RESTORE (CAS active->revoked; retained; no auto-republish) ────────────
    @Nested
    class Restore {

        @Test
        void restore_CASesActiveBanToRevoked_rowRetained_andDoesNotAutoRepublish() {
            String owner = user("restore-owner");
            seedPublicStream(ISS_X, owner);
            Authentication modX = mod(ISS_X, "mod-x");
            service.ban(modX, owner, "abuse").block();   // banned + internal
            assertThat(activeBan(owner, "brandx")).isTrue();

            OwncastModerationDto.ActionResult r = service.restore(modX, owner, "appeal upheld").block();

            assertThat(r.banned()).isFalse();
            // The ban is no longer ACTIVE...
            assertThat(activeBan(owner, "brandx")).isFalse();
            // ...but the row is RETAINED (state=revoked) = audit — the ban history row is not deleted.
            assertThat(grantRepo.historyFor(owner, "brandx").collectList().block())
                    .filteredOn(g -> g.accessType().equals(OwncastGrant.TYPE_BANNED))
                    .allSatisfy(g -> assertThat(g.state()).isEqualTo(OwncastGrant.STATE_REVOKED));
            // Does NOT auto-republish — the stream is still internal (the owner re-chooses).
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            assertThat(r.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            // Audit restore row.
            assertThat(auditRepo.historyFor(owner, "brandx").collectList().block())
                    .filteredOn(a -> a.action().equals(OwncastModerationAudit.ACTION_RESTORE))
                    .hasSize(1);
        }

        /** Restore with no active ban is a harmless no-op (still logs the action) — and after a
         *  restore the owner can re-publish (the guard no longer denies, assuming they still hold
         *  their grant). */
        @Test
        void afterRestore_ownerWithGrantCanRepublish() {
            String owner = user("restore-republish");
            Authentication streamer = streamer(ISS_X, owner);
            streamService.upsertMyStream(streamer, "show", null).block();
            broadcastAccess.grant(owner, "go live", null, admin(ISS_X, "admin-x")).block();
            streamService.setVisibility(streamer, "public").block();

            Authentication modX = mod(ISS_X, "mod-x");
            service.ban(modX, owner, "abuse").block();
            assertForbidden(streamService.setVisibility(streamer, "public"));  // denied while banned

            service.restore(modX, owner, "ok").block();
            // Now the owner (still granted) can re-publish themselves.
            assertThat(streamService.setVisibility(streamer, "public").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
        }
    }

    // ── CROSS-DOMAIN ISOLATION (the critical boundary) ────────────────────────
    @Nested
    class CrossDomainIsolation {

        /** A mod in brand X CANNOT hide/ban/restore an owner who streams in brand Y: (Y,S) is
         *  untouched — the brand-X writes resolve no brand-Y row. */
        @Test
        void modInBrandX_cannotAffectSameOwnerInBrandY() {
            String owner = user("xdom-owner");
            // The SAME owner streams (public) in BOTH brands.
            seedPublicStream(ISS_X, owner);
            seedPublicStream(ISS_Y, owner);
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
            assertThat(visibility(owner, "brandy")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);

            Authentication modX = mod(ISS_X, "mod-x");
            // KILL in brand X.
            service.ban(modX, owner, "x-abuse").block();

            // Brand X is affected: banned + internal.
            assertThat(activeBan(owner, "brandx")).isTrue();
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            // Brand Y is UNTOUCHED: no ban, still public.
            assertThat(activeBan(owner, "brandy")).isFalse();
            assertThat(visibility(owner, "brandy")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
            // The brand-Y audit log carries NO action for this owner.
            assertThat(auditRepo.historyFor(owner, "brandy").collectList().block()).isEmpty();
        }

        /** A mod in brand X hiding an owner who ONLY streams in brand Y gets a 404 (the brand-Y
         *  stream is invisible) — never touches Y. */
        @Test
        void modInBrandX_hideOfBrandYOnlyOwner_is404_neverTouchesY() {
            String owner = user("xdom-yonly");
            seedPublicStream(ISS_Y, owner);   // exists ONLY in brand Y

            StepVerifier.create(service.hide(mod(ISS_X, "mod-x"), owner, null))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                    .verify();
            // Brand Y untouched (still public).
            assertThat(visibility(owner, "brandy")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
        }

        /** A mod in brand X restoring an owner banned in brand Y is a no-op for brand Y's ban. */
        @Test
        void modInBrandX_restoreDoesNotLiftBrandYBan() {
            String owner = user("xdom-restore");
            seedPublicStream(ISS_Y, owner);
            broadcastAccess.ban(owner, "y-abuse", null, admin(ISS_Y, "admin-y")).block();
            assertThat(activeBan(owner, "brandy")).isTrue();

            // Brand-X mod restore cannot see (or lift) the brand-Y ban.
            service.restore(mod(ISS_X, "mod-x"), owner, "x-appeal").block();
            assertThat(activeBan(owner, "brandy")).isTrue();   // still banned in Y
        }

        /** A SUPERADMIN moderating is domain fixed to 'default' (NO all-brands bypass): they do
         *  NOT see/affect a brand-X or brand-Y stream through the moderation surface. */
        @Test
        void superadmin_isDomainPinned_noAllBrandsBypass() {
            String owner = user("xdom-su");
            seedPublicStream(ISS_X, owner);   // a brand-X stream

            // A SUPERADMIN's moderation domain is fixed to 'default' — the brand-X stream is invisible.
            Authentication su = principal(ISS_X, "su-1", "superadmin");
            assertThat(service.listStreams(su).collectList().block())
                    .extracting(OwncastModerationDto.StreamRow::ownerSubject)
                    .doesNotContain(owner);
            // A hide of the brand-X owner from the SUPERADMIN (fixed to 'default') is a 404.
            StepVerifier.create(service.hide(su, owner, null))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                    .verify();
            // Brand X untouched.
            assertThat(visibility(owner, "brandx")).isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
        }
    }

    // ── FAIL-CLOSED (no resolvable moderator) ─────────────────────────────────
    @Nested
    class FailClosed {

        @Test
        void nonJwtPrincipal_isUnauthorized() {
            Authentication noJwt = new UsernamePasswordAuthenticationToken(
                    "not-a-jwt", "n/a", List.of(new SimpleGrantedAuthority("ROLE_MOD")));
            StepVerifier.create(service.hide(noJwt, "bob", null))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(401))
                    .verify();
            StepVerifier.create(service.ban(noJwt, "bob", null))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(401))
                    .verify();
            StepVerifier.create(service.restore(noJwt, "bob", null))
                    .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(401))
                    .verify();
        }
    }
}
