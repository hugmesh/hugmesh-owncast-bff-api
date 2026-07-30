package systems.hugmesh.owncastbff.stream;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code owncast_stream} — the per-streamer SELF-VISIBILITY row
 * (schema in Liquibase {@code db/changelog/005-owncast-stream.xml}). Spring Data
 * {@link R2dbcRepository} over {@link OwncastStream}, matching the
 * hugmesh-federation-api reactive-repository idiom: DERIVED finders for the reads
 * (split scoped/unscoped), and {@code @Query} static-final constants ONLY for the
 * {@code now()}-stamped INSERT and the owner+domain-scoped UPDATEs (which a derived
 * method cannot express).
 *
 * <p>Every read/write is OWNER + DOMAIN scoped: the row is keyed on
 * {@code (domain, user_subject)} so a streamer can ONLY ever touch THEIR OWN stream in THEIR
 * OWN brand. A {@code null}/blank domain is the cross-domain bypass (predicate-free
 * derivation); in practice the stream surface domain-pins everyone.
 */
public interface OwncastStreamRepository extends R2dbcRepository<OwncastStream, String> {

    // ── @Query CONSTANTS (now()-stamped insert + owner+domain-scoped updates) ──

    /** DB-generated id ({@code gen_random_uuid()} DEFAULT, changelog 007) + server-side
     *  {@code now()} timestamps. The {@code id} column is OMITTED so Postgres fills it from
     *  its DEFAULT; {@code RETURNING id} reads the generated string back. */
    String INSERT_STREAM_RETURNING_ID =
            "INSERT INTO owncast_stream "
            + "(domain, user_subject, title, description, visibility, created_at, updated_at) "
            + "VALUES (:domain, :userSubject, :title, :description, :visibility, now(), now()) "
            + "RETURNING id";

    String UPDATE_META_SCOPED =
            "UPDATE owncast_stream SET title = :title, description = :description, updated_at = now() "
            + "WHERE user_subject = :userSubject AND domain = :domain";

    String UPDATE_META_UNSCOPED =
            "UPDATE owncast_stream SET title = :title, description = :description, updated_at = now() "
            + "WHERE user_subject = :userSubject";

    String UPDATE_VISIBILITY_SCOPED =
            "UPDATE owncast_stream SET visibility = :visibility, updated_at = now() "
            + "WHERE user_subject = :userSubject AND domain = :domain";

    String UPDATE_VISIBILITY_UNSCOPED =
            "UPDATE owncast_stream SET visibility = :visibility, updated_at = now() "
            + "WHERE user_subject = :userSubject";

    // ── derived reads: scoped (AND domain = ?) vs unscoped (cross-domain bypass) ──

    /** The stream owned by a subject in a brand (owner + domain scoped). */
    Mono<OwncastStream> findByUserSubjectAndDomain(String userSubject, String domain);

    /** The stream owned by a subject (cross-domain bypass — no domain predicate). */
    Mono<OwncastStream> findByUserSubject(String userSubject);

    /** Every stream IN a brand, ordered by owner — the MODERATION list surface. */
    Flux<OwncastStream> findByDomainOrderByUserSubjectAsc(String domain);

    /** Every stream across brands, ordered by owner (cross-domain bypass). */
    Flux<OwncastStream> findAllByOrderByUserSubjectAsc();

    // ── @Query writes ──────────────────────────────────────────────────

    /** The INSERT ... RETURNING id — omits the id (the {@code gen_random_uuid()} DEFAULT
     *  fills it) and yields the DB-generated id string back. NON-{@code @Modifying}: a
     *  value-returning statement, not a row-count. */
    @Query(INSERT_STREAM_RETURNING_ID)
    Mono<String> insertRow(@Param("domain") String domain,
                           @Param("userSubject") String userSubject, @Param("title") String title,
                           @Param("description") String description, @Param("visibility") String visibility);

    @Modifying
    @Query(UPDATE_META_SCOPED)
    Mono<Long> updateMetaScoped(@Param("userSubject") String userSubject, @Param("title") String title,
                                @Param("description") String description, @Param("domain") String domain);

    @Modifying
    @Query(UPDATE_META_UNSCOPED)
    Mono<Long> updateMetaUnscoped(@Param("userSubject") String userSubject, @Param("title") String title,
                                  @Param("description") String description);

    @Modifying
    @Query(UPDATE_VISIBILITY_SCOPED)
    Mono<Long> updateVisibilityScoped(@Param("userSubject") String userSubject,
                                      @Param("visibility") String visibility, @Param("domain") String domain);

    @Modifying
    @Query(UPDATE_VISIBILITY_UNSCOPED)
    Mono<Long> updateVisibilityUnscoped(@Param("userSubject") String userSubject,
                                        @Param("visibility") String visibility);

    // ── public API (preserves original method shapes; dispatch on scope) ──────

    /** The stream OWNED by {@code userSubject} in their brand, or empty if they have none. */
    default Mono<OwncastStream> findForOwner(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? findByUserSubject(userSubject)
                : findByUserSubjectAndDomain(userSubject, domain);
    }

    /** Every stream IN a brand — the MODERATION list surface (ordered by owner). */
    default Flux<OwncastStream> listInDomain(String domain) {
        return DomainScope.isUnscoped(domain)
                ? findAllByOrderByUserSubjectAsc()
                : findByDomainOrderByUserSubjectAsc(domain);
    }

    /**
     * Insert a NEW stream owned by {@code userSubject} in {@code domain} with the given
     * title/description and visibility, returning it. The {@code domain} is defaulted to
     * the platform {@code default} for an unscoped write so a stamped row always carries a
     * concrete brand.
     */
    default Mono<OwncastStream> insert(String userSubject, String title, String description,
                                       String visibility, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        Instant now = Instant.now();
        // The id is DB-generated (gen_random_uuid() DEFAULT, changelog 007): the INSERT
        // omits it and RETURNING id hands back the generated string, which we render into
        // the returned row (same fields/values as before — only the id SOURCE moved).
        return insertRow(dom, userSubject, title, description, visibility)
                .map(genId -> new OwncastStream(genId, dom, userSubject, title, description, visibility,
                        now, now));
    }

    /**
     * Update the title/description of the stream owned by {@code userSubject} in {@code domain}
     * (bumping {@code updated_at}). Owner + domain scoped so it can NEVER touch another
     * principal's or brand's row. Returns the rows-updated count (0 = no such owned stream).
     */
    default Mono<Long> updateMeta(String userSubject, String title, String description, String domain) {
        return DomainScope.isUnscoped(domain)
                ? updateMetaUnscoped(userSubject, title, description)
                : updateMetaScoped(userSubject, title, description, domain);
    }

    /**
     * Set the visibility of the stream owned by {@code userSubject} in {@code domain}
     * (bumping {@code updated_at}). Owner + domain scoped. Returns the rows-updated count
     * (0 = no such owned stream).
     */
    default Mono<Long> setVisibility(String userSubject, String visibility, String domain) {
        return DomainScope.isUnscoped(domain)
                ? updateVisibilityUnscoped(userSubject, visibility)
                : updateVisibilityScoped(userSubject, visibility, domain);
    }
}
