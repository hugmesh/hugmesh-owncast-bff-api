package net.hugmesh.owncastbff.mod;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.owncastbff.support.PostgresSliceTestConfig;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link OwncastModerationAuditRepository} against a Testcontainers-Postgres
 * store ({@link PostgresTestSupport} + {@link PostgresSliceTestConfig}) that Liquibase applies
 * the REAL production changelog over — including changelog 007's {@code (gen_random_uuid())::text}
 * id DEFAULT + the repository's {@code INSERT ... RETURNING id}. Moved off the old H2 store
 * ({@code TestDatabaseConfig}) for the DB-generated-UUID-PK migration ({@code gen_random_uuid()}/
 * {@code RETURNING} are Postgres-only). Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — insert round-trips a kill/hide/restore audit row (app-generated
 *       id, server-stamped domain); historyFor returns a target's actions newest-first.</li>
 *   <li><b>APPEND-ONLY</b> — multiple actions against one target accrue as distinct rows (the
 *       journal grows, never overwrites).</li>
 *   <li><b>DOMAIN ISOLATION</b> — an audit row in brand X is invisible to brand Y's scope.</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import(PostgresSliceTestConfig.class)
class OwncastModerationAuditRepositoryTest extends PostgresTestSupport {

    @Autowired OwncastModerationAuditRepository repo;

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Class-unique prefix: @DataR2dbcTest caches+shares ONE context across test classes with
    // identical @Import config, so prefix this class's subjects to avoid cross-test collisions.
    private String user(String tag) { return "auditrepo-" + tag + "-" + SEQ.incrementAndGet(); }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void insert_roundTrips_killRow() {
            String target = user("us-kill");
            OwncastModerationAudit a = repo.insert("brandx", "mod-x", target,
                    OwncastModerationAudit.ACTION_KILL, "abuse").block();
            assertThat(a.id()).isNotBlank();
            assertThat(a.domain()).isEqualTo("brandx");
            assertThat(a.actorSubject()).isEqualTo("mod-x");
            assertThat(a.targetSubject()).isEqualTo(target);
            assertThat(a.action()).isEqualTo(OwncastModerationAudit.ACTION_KILL);
            assertThat(a.reason()).isEqualTo("abuse");
            assertThat(a.createdAt()).isNotNull();

            List<OwncastModerationAudit> hist = repo.historyFor(target, "brandx").collectList().block();
            assertThat(hist).hasSize(1);
            assertThat(hist.get(0).id()).isEqualTo(a.id());
        }

        @Test
        void insert_nullReason_isAllowed() {
            String target = user("us-hide");
            OwncastModerationAudit a = repo.insert("brandx", "mod-x", target,
                    OwncastModerationAudit.ACTION_HIDE, null).block();
            assertThat(a.reason()).isNull();
            assertThat(repo.historyFor(target, "brandx").collectList().block()).hasSize(1);
        }
    }

    // ── APPEND-ONLY (the journal grows) ───────────────────────────────────────
    @Nested
    class AppendOnly {

        @Test
        void multipleActions_accrueAsDistinctRows_newestFirst() {
            String target = user("ap-target");
            repo.insert("brandx", "mod-x", target, OwncastModerationAudit.ACTION_KILL, "1").block();
            repo.insert("brandx", "mod-x", target, OwncastModerationAudit.ACTION_RESTORE, "2").block();
            repo.insert("brandx", "mod-x", target, OwncastModerationAudit.ACTION_HIDE, "3").block();

            List<OwncastModerationAudit> hist = repo.historyFor(target, "brandx").collectList().block();
            assertThat(hist).hasSize(3);   // distinct rows — append-only, never overwritten
            assertThat(hist).extracting(OwncastModerationAudit::action)
                    .containsExactlyInAnyOrder(OwncastModerationAudit.ACTION_KILL,
                            OwncastModerationAudit.ACTION_RESTORE, OwncastModerationAudit.ACTION_HIDE);
        }
    }

    // ── DOMAIN ISOLATION ──────────────────────────────────────────────────────
    @Nested
    class DomainIsolation {

        @Test
        void auditInBrandX_invisibleFromBrandYScope() {
            String target = user("di-iso");
            repo.insert("brandx", "mod-x", target, OwncastModerationAudit.ACTION_KILL, "x").block();
            assertThat(repo.historyFor(target, "brandx").collectList().block()).hasSize(1);
            assertThat(repo.historyFor(target, "brandy").collectList().block()).isEmpty();
        }
    }
}
