package systems.hugmesh.owncastbff.mod;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code owncast_moderation_audit} — the APPEND-ONLY moderator-action
 * journal (schema in Liquibase {@code db/changelog/006-owncast-moderation-audit.xml}). Spring Data
 * {@link R2dbcRepository} over {@link OwncastModerationAudit}, matching the
 * hugmesh-federation-api reactive-repository idiom: a DERIVED finder for the read (split
 * scoped/unscoped) and one {@code @Query} static-final constant for the {@code now()}-stamped
 * append (which a derived method cannot express).
 *
 * <p>This table is APPEND-ONLY: the only write is {@link #insert} (no update / delete). The
 * READS are DOMAIN-scoped: a scoped moderator only ever resolves rows in THEIR brand; a
 * {@code null}/blank domain would be the cross-domain bypass — but moderation domain-pins
 * EVERYONE, so the read is always called with a concrete domain.
 */
public interface OwncastModerationAuditRepository
        extends R2dbcRepository<OwncastModerationAudit, String> {

    /** DB-generated id ({@code gen_random_uuid()} DEFAULT, changelog 007) + server-side
     *  {@code now()} created_at. The {@code id} column is OMITTED so Postgres fills it from
     *  its DEFAULT; {@code RETURNING id} reads the generated string back. */
    String INSERT_AUDIT_RETURNING_ID =
            "INSERT INTO owncast_moderation_audit "
            + "(domain, actor_subject, target_subject, action, reason, created_at) "
            + "VALUES (:domain, :actorSubject, :targetSubject, :action, :reason, now()) "
            + "RETURNING id";

    // ── derived reads: scoped (AND domain = ?) vs unscoped (cross-domain bypass) ──

    Flux<OwncastModerationAudit> findByTargetSubjectAndDomainOrderByCreatedAtDescIdAsc(
            String targetSubject, String domain);

    Flux<OwncastModerationAudit> findByTargetSubjectOrderByCreatedAtDescIdAsc(String targetSubject);

    // ── @Query write ───────────────────────────────────────────────────

    /** The INSERT ... RETURNING id — omits the id (the {@code gen_random_uuid()} DEFAULT
     *  fills it) and yields the DB-generated id string back. NON-{@code @Modifying}: a
     *  value-returning statement, not a row-count. */
    @Query(INSERT_AUDIT_RETURNING_ID)
    Mono<String> insertRow(@Param("domain") String domain,
                           @Param("actorSubject") String actorSubject,
                           @Param("targetSubject") String targetSubject,
                           @Param("action") String action, @Param("reason") String reason);

    // ── public API (preserves original method shapes) ────────────────────

    /**
     * APPEND a moderator-action row (app-generated id) in the moderator's brand and return it.
     * A blank/null scope is defaulted to the platform {@code default} domain so a stamped row
     * always carries a concrete brand.
     */
    default Mono<OwncastModerationAudit> insert(String domain, String actorSubject, String targetSubject,
                                                String action, String reason) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        // The id is DB-generated (gen_random_uuid() DEFAULT, changelog 007): the INSERT
        // omits it and RETURNING id hands back the generated string, which we render into
        // the returned row (same fields/values as before — only the id SOURCE moved).
        return insertRow(dom, actorSubject, targetSubject, action, reason)
                .map(genId -> new OwncastModerationAudit(genId, dom, actorSubject, targetSubject,
                        action, reason, Instant.now()));
    }

    /** The action journal for a TARGET within a brand (newest first) — the audit read. */
    default Flux<OwncastModerationAudit> historyFor(String targetSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? findByTargetSubjectOrderByCreatedAtDescIdAsc(targetSubject)
                : findByTargetSubjectAndDomainOrderByCreatedAtDescIdAsc(targetSubject, domain);
    }
}
