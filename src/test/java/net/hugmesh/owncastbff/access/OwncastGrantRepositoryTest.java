package net.hugmesh.owncastbff.access;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Flux;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.owncastbff.support.PostgresSliceTestConfig;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link OwncastGrantRepository} against a Testcontainers-Postgres
 * store ({@link PostgresTestSupport} + {@link PostgresSliceTestConfig}) that Liquibase
 * applies the REAL production changelog over — including changelog 007's
 * {@code (gen_random_uuid())::text} id DEFAULT + the repository's {@code INSERT ... RETURNING
 * id}. Moved off the old H2 PostgreSQL-compat store ({@code TestDatabaseConfig}) because the
 * DB-generated-UUID-PK migration needs {@code pgcrypto}/{@code gen_random_uuid()} and a
 * reliable {@code INSERT ... RETURNING}, NEITHER of which H2 provides. Delineated per the
 * test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — insert active grant/ban round-trips; CAS active->revoked
 *       stamps revoked_at and is the only transition (the row is RETAINED = audit, never
 *       deleted); a timed ban carries a future expires_at.</li>
 *   <li><b>CROSS-USER (DENY isolation + domain isolation)</b> — an override in brand X is
 *       invisible to brand Y's scope; findActive is brand-scoped; SUPERADMIN (null domain)
 *       reads every brand's.</li>
 *   <li><b>CONCURRENT-CONFLICTING</b> — many concurrent revokes of one row: exactly one
 *       CAS wins (active->revoked), the rest update zero rows.</li>
 * </ul>
 *
 * <p>The partial-unique invariant (one ACTIVE row per (domain,user,type)) is a PG-only
 * partial index; on this real-Postgres store it now applies for real. The
 * at-most-one-active invariant the SERVICE enforces is exercised in
 * {@link OwncastBroadcastServiceTest}. Here we prove the audit-retain + CAS + domain-scope
 * semantics, plus the DB-generated id round-trip, on the real Postgres slice store.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import(PostgresSliceTestConfig.class)
class OwncastGrantRepositoryTest extends PostgresTestSupport {

    @Autowired OwncastGrantRepository repo;

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Class-unique prefix: @DataR2dbcTest caches+shares ONE context (one H2 mem store)
    // across test classes with identical @Import config, so a bare per-class SEQ would
    // collide subjects with the service/guard slice tests. The "repo" tag keeps this
    // class's rows distinct in the shared store.
    private String user(String tag) { return "repo-" + tag + "-" + SEQ.incrementAndGet(); }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void insertActiveBroadcastGrant_roundTrips() {
            String u = user("us-grant");
            OwncastGrant a = repo.insertActive(u, OwncastGrant.TYPE_BROADCAST, null, "welcome", "admin-x", "brandx").block();
            assertThat(a.id()).isNotBlank();
            assertThat(a.isActive()).isTrue();
            assertThat(a.accessType()).isEqualTo(OwncastGrant.TYPE_BROADCAST);
            assertThat(a.expiresAt()).isNull();           // permanent grant
            assertThat(a.domain()).isEqualTo("brandx");
            assertThat(a.grantedBySubject()).isEqualTo("admin-x");

            OwncastGrant found = repo.findActive(u, OwncastGrant.TYPE_BROADCAST, "brandx").block();
            assertThat(found).isNotNull();
            assertThat(found.id()).isEqualTo(a.id());
        }

        @Test
        void timedBan_carriesFutureExpiry() {
            String u = user("us-timeout");
            Instant exp = Instant.now().plusSeconds(3600);
            OwncastGrant a = repo.insertActive(u, OwncastGrant.TYPE_BANNED, exp, "cooldown", "admin-x", "brandx").block();
            assertThat(a.accessType()).isEqualTo(OwncastGrant.TYPE_BANNED);
            assertThat(a.expiresAt()).isNotNull();
            assertThat(a.isEffectiveAt(Instant.now())).isTrue();              // in force now
            assertThat(a.isEffectiveAt(exp.plusSeconds(1))).isFalse();        // auto-restored after TTL
        }

        @Test
        void revoke_CASesActiveToRevoked_andRowIsRetainedAsAudit() {
            String u = user("us-revoke");
            OwncastGrant a = repo.insertActive(u, OwncastGrant.TYPE_BANNED, null, "bad", "admin-x", "brandx").block();

            assertThat(repo.revoke(a.id()).block()).isEqualTo(1L);   // CAS won
            // No longer active...
            assertThat(repo.findActive(u, OwncastGrant.TYPE_BANNED, "brandx").blockOptional()).isEmpty();
            // ...but the row is RETAINED (state=revoked, revoked_at stamped) = audit trail.
            List<OwncastGrant> hist = repo.historyFor(u, "brandx").collectList().block();
            assertThat(hist).hasSize(1);
            assertThat(hist.get(0).state()).isEqualTo(OwncastGrant.STATE_REVOKED);
            assertThat(hist.get(0).revokedAt()).isNotNull();
        }

        @Test
        void revoke_ofAlreadyRevoked_isNoOp() {
            String u = user("us-revoke2");
            OwncastGrant a = repo.insertActive(u, OwncastGrant.TYPE_BROADCAST, null, null, "admin-x", "brandx").block();
            assertThat(repo.revoke(a.id()).block()).isEqualTo(1L);
            assertThat(repo.revoke(a.id()).block()).isEqualTo(0L);  // already revoked — CAS matches nothing
        }
    }

    // ── CROSS-USER (DENY isolation + domain isolation) ────────────────────────
    @Nested
    class CrossUser {

        @Test
        void override_isInvisibleFromAnotherBrandScope() {
            String u = user("cu-iso");
            repo.insertActive(u, OwncastGrant.TYPE_BROADCAST, null, null, "admin-x", "brandx").block();
            assertThat(repo.findActive(u, OwncastGrant.TYPE_BROADCAST, "brandx").block()).isNotNull();
            // brandy's scope cannot see brandx's override.
            assertThat(repo.findActive(u, OwncastGrant.TYPE_BROADCAST, "brandy").blockOptional()).isEmpty();
            assertThat(repo.activeFor(u, "brandy").collectList().block()).isEmpty();
        }

        @Test
        void sameUser_independentOverridesPerBrand() {
            String u = user("cu-perbrand");
            repo.insertActive(u, OwncastGrant.TYPE_BANNED, null, "x-ban", "admin-x", "brandx").block();
            repo.insertActive(u, OwncastGrant.TYPE_BROADCAST, null, "y-grant", "admin-y", "brandy").block();

            assertThat(repo.findActive(u, OwncastGrant.TYPE_BANNED, "brandx").block()).isNotNull();
            assertThat(repo.findActive(u, OwncastGrant.TYPE_BANNED, "brandy").blockOptional()).isEmpty();
            assertThat(repo.findActive(u, OwncastGrant.TYPE_BROADCAST, "brandy").block()).isNotNull();
        }

        @Test
        void superadmin_nullDomain_seesEveryBrand() {
            String u = user("cu-su");
            repo.insertActive(u, OwncastGrant.TYPE_BROADCAST, null, null, "admin-x", "su-bx").block();
            // The null-domain bypass resolves the override regardless of brand.
            OwncastGrant got = repo.findActive(u, OwncastGrant.TYPE_BROADCAST, null).block();
            assertThat(got).isNotNull();
            assertThat(got.domain()).isEqualTo("su-bx");
        }

        @Test
        void listActive_domainScoped_neverCrossesBrands() {
            String u = user("cu-list");
            repo.insertActive(u + "-x", OwncastGrant.TYPE_BROADCAST, null, null, "a", "isl-bx").block();
            repo.insertActive(u + "-y", OwncastGrant.TYPE_BROADCAST, null, null, "a", "isl-by").block();

            assertThat(repo.listActive("isl-bx").collectList().block())
                    .allSatisfy(a -> assertThat(a.domain()).isEqualTo("isl-bx"));
            assertThat(repo.listActive("isl-by").collectList().block())
                    .allSatisfy(a -> assertThat(a.domain()).isEqualTo("isl-by"));
        }
    }

    // ── CONCURRENT-CONFLICTING (CAS revoke) ───────────────────────────────────
    @Nested
    class ConcurrentConflicting {

        /** Many concurrent revokes of ONE active row: the CAS active->revoked serializes
         *  them — exactly ONE wins (rows-updated 1), the rest match zero rows. */
        @Test
        void concurrentRevokes_exactlyOneWins() {
            String u = user("cc-revoke");
            OwncastGrant a = repo.insertActive(u, OwncastGrant.TYPE_BANNED, null, null, "admin-x", "brandx").block();

            int racers = 20;
            Long winners = Flux.range(0, racers)
                    .flatMap(i -> repo.revoke(a.id()))
                    .reduce(0L, Long::sum)
                    .block(Duration.ofSeconds(30));

            assertThat(winners).isEqualTo(1L);   // exactly one CAS landed active->revoked
            assertThat(repo.historyFor(u, "brandx").collectList().block()).hasSize(1);  // one row, retained
        }
    }
}
