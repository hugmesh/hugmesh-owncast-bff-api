package systems.hugmesh.owncastbff.access;

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
 * Reactive (R2DBC) store for {@code owncast_grant} — the broadcast grant/timeout/ban
 * OVERLAY's desired-state table (schema in Liquibase
 * {@code db/changelog/004-owncast-grant.xml}). Spring Data {@link R2dbcRepository}
 * over the {@link OwncastGrant} entity, matching the
 * hugmesh-federation-api reactive-repository idiom: DERIVED query methods for the
 * reads (split scoped/unscoped so the SUPERADMIN cross-domain bypass is a distinct
 * predicate-free derivation rather than a spliced fragment), and {@code @Query}
 * static-final constants ONLY where derivation cannot express the semantics (the
 * {@code now()}-stamped INSERT and the guarded CAS {@code active -> revoked} UPDATE).
 *
 * <p>The service NEVER deletes a row — a restore/revoke is a CAS
 * {@code active -> revoked} ({@link #revoke}) so the table stays the audit trail.
 * {@link #insertActive} relies on the partial UNIQUE index
 * {@code (domain, user_subject, access_type) WHERE state='active'} so a concurrent
 * double-grant/ban surfaces as a unique-violation (PG) the service treats as
 * "already set"; on H2 the service's findActive-before-insert is the guard.
 *
 * <p>The READS are DOMAIN-scoped: a scoped admin only ever resolves rows in THEIR
 * brand (the {@code *AndDomain*} derivations); a {@code null}/blank domain is the
 * SUPERADMIN cross-domain bypass (the predicate-free derivations). The public
 * methods keep the original signatures and dispatch on {@link DomainScope#isUnscoped}.
 */
public interface OwncastGrantRepository extends R2dbcRepository<OwncastGrant, String> {

    // ── @Query CONSTANTS (insert + CAS update — derivation cannot express now()/guarded CAS) ──

    /** DB-generated id ({@code gen_random_uuid()} DEFAULT, changelog 007) + server-side
     *  {@code now()} created_at. The {@code id} column is OMITTED so Postgres fills it from
     *  its DEFAULT; {@code RETURNING id} reads the generated string back. A plain
     *  (non-{@code @Modifying}) {@code @Query} returning the new id. */
    String INSERT_ACTIVE_RETURNING_ID =
            "INSERT INTO owncast_grant "
            + "(domain, user_subject, access_type, state, granted_by_subject, "
            + " reason, created_at, expires_at, revoked_at) "
            + "VALUES (:domain, :userSubject, :accessType, 'active', :grantedBy, "
            + " :reason, now(), :expiresAt, NULL) "
            + "RETURNING id";

    /** CAS {@code active -> revoked} for one id, stamping {@code revoked_at}; guarded on
     *  the current state so only ONE writer wins (rows-updated 1 = won, 0 = already revoked). */
    String REVOKE_ACTIVE =
            "UPDATE owncast_grant SET state = 'revoked', revoked_at = now() "
            + "WHERE id = :id AND state = 'active'";

    // ── derived reads: scoped (AND domain = ?) vs unscoped (SUPERADMIN bypass) ──

    Mono<OwncastGrant> findFirstByUserSubjectAndAccessTypeAndStateAndDomainOrderByCreatedAtDescIdAsc(
            String userSubject, String accessType, String state, String domain);

    Mono<OwncastGrant> findFirstByUserSubjectAndAccessTypeAndStateOrderByCreatedAtDescIdAsc(
            String userSubject, String accessType, String state);

    Flux<OwncastGrant> findByUserSubjectAndStateAndDomainOrderByAccessTypeAscCreatedAtDesc(
            String userSubject, String state, String domain);

    Flux<OwncastGrant> findByUserSubjectAndStateOrderByAccessTypeAscCreatedAtDesc(
            String userSubject, String state);

    Flux<OwncastGrant> findByStateAndDomainOrderByDomainAscUserSubjectAscAccessTypeAsc(
            String state, String domain);

    Flux<OwncastGrant> findByStateOrderByDomainAscUserSubjectAscAccessTypeAsc(String state);

    Flux<OwncastGrant> findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(
            String userSubject, String domain);

    Flux<OwncastGrant> findByUserSubjectOrderByCreatedAtDescIdAsc(String userSubject);

    // ── @Query writes ──────────────────────────────────────────────────

    /** The INSERT ... RETURNING id — omits the id (the {@code gen_random_uuid()} DEFAULT
     *  fills it) and yields the DB-generated id string back. NON-{@code @Modifying}: it
     *  is a value-returning statement, not a row-count. */
    @Query(INSERT_ACTIVE_RETURNING_ID)
    Mono<String> insertActiveRow(@Param("domain") String domain,
                                 @Param("userSubject") String userSubject,
                                 @Param("accessType") String accessType,
                                 @Param("grantedBy") String grantedBy,
                                 @Param("reason") String reason,
                                 @Param("expiresAt") Instant expiresAt);

    /**
     * Compare-and-swap {@code active -> revoked} for one row id (rows-updated count:
     * 1 = this caller won, 0 = already revoked). The row is never deleted — the revoke
     * is the audit of WHEN the override was lifted.
     */
    @Modifying
    @Query(REVOKE_ACTIVE)
    Mono<Long> revoke(@Param("id") String id);

    // ── public API (preserves original method shapes; dispatch on scope) ──────

    /**
     * Insert a new ACTIVE override (app-generated id) in the given brand and return it.
     * {@code expiresAt} null = PERMANENT; a future instant = a TIMEOUT. The {@code domain}
     * is defaulted to the platform {@code default} for a SUPERADMIN unscoped write so a
     * stamped row always carries a concrete brand.
     */
    default Mono<OwncastGrant> insertActive(String userSubject, String accessType, Instant expiresAt,
                                            String reason, String grantedBy, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        // The id is DB-generated (gen_random_uuid() DEFAULT, changelog 007): the INSERT
        // omits it and RETURNING id hands back the generated string, which we render into
        // the returned row (same fields/values as before — only the id SOURCE moved).
        return insertActiveRow(dom, userSubject, accessType, grantedBy, reason, expiresAt)
                .map(genId -> new OwncastGrant(genId, dom, userSubject, accessType,
                        OwncastGrant.STATE_ACTIVE, grantedBy, reason, Instant.now(), expiresAt, null));
    }

    /**
     * The active override of a given type for a (user) VISIBLE to the given tenant scope.
     * A scoped admin only ever resolves a row in THEIR brand; SUPERADMIN ({@code null}
     * domain) resolves it in any brand.
     */
    default Mono<OwncastGrant> findActive(String userSubject, String accessType, String domain) {
        return DomainScope.isUnscoped(domain)
                ? findFirstByUserSubjectAndAccessTypeAndStateOrderByCreatedAtDescIdAsc(
                        userSubject, accessType, OwncastGrant.STATE_ACTIVE)
                : findFirstByUserSubjectAndAccessTypeAndStateAndDomainOrderByCreatedAtDescIdAsc(
                        userSubject, accessType, OwncastGrant.STATE_ACTIVE, domain);
    }

    /**
     * Every ACTIVE override for a principal WITHIN a brand — the request-time enforcement
     * working set. A {@code null} domain is the SUPERADMIN cross-domain bypass.
     */
    default Flux<OwncastGrant> activeFor(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? findByUserSubjectAndStateOrderByAccessTypeAscCreatedAtDesc(
                        userSubject, OwncastGrant.STATE_ACTIVE)
                : findByUserSubjectAndStateAndDomainOrderByAccessTypeAscCreatedAtDesc(
                        userSubject, OwncastGrant.STATE_ACTIVE, domain);
    }

    /** All ACTIVE overrides VISIBLE to the given tenant scope — the MANAGE read surface. */
    default Flux<OwncastGrant> listActive(String domain) {
        return DomainScope.isUnscoped(domain)
                ? findByStateOrderByDomainAscUserSubjectAscAccessTypeAsc(OwncastGrant.STATE_ACTIVE)
                : findByStateAndDomainOrderByDomainAscUserSubjectAscAccessTypeAsc(
                        OwncastGrant.STATE_ACTIVE, domain);
    }

    /** The full history (active + revoked) for a principal WITHIN a brand — the audit read. */
    default Flux<OwncastGrant> historyFor(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? findByUserSubjectOrderByCreatedAtDescIdAsc(userSubject)
                : findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(userSubject, domain);
    }
}
