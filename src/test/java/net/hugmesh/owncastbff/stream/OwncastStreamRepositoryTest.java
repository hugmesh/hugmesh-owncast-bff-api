package net.hugmesh.owncastbff.stream;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.owncastbff.support.PostgresSliceTestConfig;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link OwncastStreamRepository} against a Testcontainers-Postgres
 * store ({@link PostgresTestSupport} + {@link PostgresSliceTestConfig}) that Liquibase
 * applies the REAL production changelog over — including changelog 007's
 * {@code (gen_random_uuid())::text} id DEFAULT + the repository's {@code INSERT ... RETURNING
 * id}. Moved off the old H2 store ({@code TestDatabaseConfig}) for the DB-generated-UUID-PK
 * migration ({@code gen_random_uuid()}/{@code RETURNING} are Postgres-only). Delineated per
 * the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — insert round-trips a stream owned by a subject; updateMeta
 *       changes title/description (owner-scoped); setVisibility flips the flag (owner-scoped);
 *       a default-internal insert.</li>
 *   <li><b>CROSS-USER (DENY isolation)</b> — a write scoped to owner A does NOT touch owner B's
 *       stream; findForOwner only resolves the asking owner's row.</li>
 *   <li><b>DOMAIN ISOLATION</b> — a stream in brand X is invisible to brand Y's scope; the same
 *       subject has independent streams per brand.</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import(PostgresSliceTestConfig.class)
class OwncastStreamRepositoryTest extends PostgresTestSupport {

    @Autowired OwncastStreamRepository repo;

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Class-unique prefix: @DataR2dbcTest caches+shares ONE context across test classes with
    // identical @Import config, so prefix this class's subjects to avoid cross-test collisions.
    private String user(String tag) { return "strepo-" + tag + "-" + SEQ.incrementAndGet(); }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void insert_roundTrips_internalByDefaultValue() {
            String u = user("us-insert");
            OwncastStream s = repo.insert(u, "My Show", "nightly", OwncastStream.VISIBILITY_INTERNAL, "brandx").block();
            assertThat(s.id()).isNotBlank();
            assertThat(s.userSubject()).isEqualTo(u);
            assertThat(s.domain()).isEqualTo("brandx");
            assertThat(s.title()).isEqualTo("My Show");
            assertThat(s.description()).isEqualTo("nightly");
            assertThat(s.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL);

            OwncastStream found = repo.findForOwner(u, "brandx").block();
            assertThat(found).isNotNull();
            assertThat(found.id()).isEqualTo(s.id());
        }

        @Test
        void updateMeta_changesTitleAndDescription_ownerScoped() {
            String u = user("us-meta");
            repo.insert(u, "old", "olddesc", OwncastStream.VISIBILITY_INTERNAL, "brandx").block();

            assertThat(repo.updateMeta(u, "new", "newdesc", "brandx").block()).isEqualTo(1L);
            OwncastStream found = repo.findForOwner(u, "brandx").block();
            assertThat(found.title()).isEqualTo("new");
            assertThat(found.description()).isEqualTo("newdesc");
            assertThat(found.visibility()).isEqualTo(OwncastStream.VISIBILITY_INTERNAL); // unchanged
        }

        @Test
        void setVisibility_flipsFlag_ownerScoped() {
            String u = user("us-vis");
            repo.insert(u, "t", "d", OwncastStream.VISIBILITY_INTERNAL, "brandx").block();

            assertThat(repo.setVisibility(u, OwncastStream.VISIBILITY_PUBLIC, "brandx").block()).isEqualTo(1L);
            assertThat(repo.findForOwner(u, "brandx").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_PUBLIC);

            assertThat(repo.setVisibility(u, OwncastStream.VISIBILITY_INTERNAL, "brandx").block()).isEqualTo(1L);
            assertThat(repo.findForOwner(u, "brandx").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }

        @Test
        void updateMeta_noStream_updatesZeroRows() {
            String u = user("us-none");
            assertThat(repo.updateMeta(u, "t", "d", "brandx").block()).isEqualTo(0L);
            assertThat(repo.setVisibility(u, OwncastStream.VISIBILITY_PUBLIC, "brandx").block()).isEqualTo(0L);
        }
    }

    // ── CROSS-USER (DENY isolation) ───────────────────────────────────────────
    @Nested
    class CrossUser {

        @Test
        void findForOwner_resolvesOnlyTheAskingOwnersRow() {
            String a = user("cu-a");
            String b = user("cu-b");
            repo.insert(a, "a-title", null, OwncastStream.VISIBILITY_INTERNAL, "brandx").block();
            repo.insert(b, "b-title", null, OwncastStream.VISIBILITY_INTERNAL, "brandx").block();

            assertThat(repo.findForOwner(a, "brandx").block().title()).isEqualTo("a-title");
            assertThat(repo.findForOwner(b, "brandx").block().title()).isEqualTo("b-title");
        }

        @Test
        void write_scopedToOneOwner_doesNotTouchAnother() {
            String a = user("cu-wa");
            String b = user("cu-wb");
            repo.insert(a, "a", "a", OwncastStream.VISIBILITY_INTERNAL, "brandx").block();
            repo.insert(b, "b", "b", OwncastStream.VISIBILITY_INTERNAL, "brandx").block();

            // A flip for owner A leaves owner B untouched.
            repo.setVisibility(a, OwncastStream.VISIBILITY_PUBLIC, "brandx").block();
            assertThat(repo.findForOwner(a, "brandx").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
            assertThat(repo.findForOwner(b, "brandx").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
        }
    }

    // ── DOMAIN ISOLATION ──────────────────────────────────────────────────────
    @Nested
    class DomainIsolation {

        @Test
        void streamInBrandX_invisibleFromBrandYScope() {
            String u = user("di-iso");
            repo.insert(u, "x-show", null, OwncastStream.VISIBILITY_INTERNAL, "brandx").block();
            assertThat(repo.findForOwner(u, "brandx").block()).isNotNull();
            assertThat(repo.findForOwner(u, "brandy").blockOptional()).isEmpty();
        }

        @Test
        void sameSubject_independentStreamsPerBrand() {
            String u = user("di-perbrand");
            repo.insert(u, "x", null, OwncastStream.VISIBILITY_INTERNAL, "brandx").block();
            repo.insert(u, "y", null, OwncastStream.VISIBILITY_PUBLIC, "brandy").block();

            assertThat(repo.findForOwner(u, "brandx").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_INTERNAL);
            assertThat(repo.findForOwner(u, "brandy").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_PUBLIC);

            // A brand-X flip does NOT cross into brand Y.
            repo.setVisibility(u, OwncastStream.VISIBILITY_PUBLIC, "brandx").block();
            assertThat(repo.findForOwner(u, "brandy").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_PUBLIC); // brand Y unchanged (was already public)
            assertThat(repo.findForOwner(u, "brandx").block().visibility())
                    .isEqualTo(OwncastStream.VISIBILITY_PUBLIC);
        }
    }
}
