package systems.hugmesh.owncastbff.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.owncastbff.security.PrincipalDomain;

import java.time.Duration;
import java.time.Instant;

/**
 * The desired-state write surface for the {@code owncast_grant} broadcast
 * grant/timeout/ban overlay — the API the {@link OwncastBroadcastController} endpoints
 * call. CLONED in semantics from the wiki-bff {@code WikiAccessService}: it is
 * DELIBERATELY the only write surface for the overlay; it writes/CASes the table and
 * NEVER touches Casdoor or the gateway directly. The request-time enforcement
 * ({@link OwncastBroadcastGuard}) is the sole reader of the table on the broadcast path,
 * so a write here changes who may broadcast on the next request.
 *
 * <p>All writes are DOMAIN-scoped: the acting principal's brand is derived SERVER-SIDE
 * from the validated issuer ({@link PrincipalDomain}) and stamped on the row, so a scoped
 * ADMIN of brand X can only grant/ban/restore WITHIN brand X. A SUPERADMIN has a
 * {@code null} (cross-domain) scope and therefore cannot derive a victim brand from its own
 * issuer: in MULTI-BRAND mode it must name the target brand via {@code targetDomain}, which
 * is validated against the trusted registry and FAILS CLOSED with a {@code 400} when
 * absent/unknown — a row stamped {@code default} is one the brand-scoped
 * {@link OwncastBroadcastGuard} read never matches, i.e. a ban that returns 200 but does
 * nothing. In SINGLE-ISSUER mode every principal is {@code default}, so a SUPERADMIN write
 * keeps the legacy {@code default} brand (behaviour unchanged). See {@link #writeDomain}.
 *
 * <ul>
 *   <li>{@link #grant} — give a USER an ACTIVE permanent {@code broadcast} override
 *       (expires_at NULL) — the ONLY way to confer may-broadcast (default-deny).</li>
 *   <li>{@link #timeout} — a {@code banned} override with a FUTURE expires_at: it DENIES
 *       broadcast until the TTL, then auto-restores (the enforcement read treats an
 *       expired row as inactive — no write needed on expiry).</li>
 *   <li>{@link #ban} — an ACTIVE permanent {@code banned} override (expires_at NULL).</li>
 *   <li>{@link #revoke} — CAS the active override of a type to {@code revoked} (the row
 *       is retained = audit). Restoring broadcast = revoke the {@code banned} row;
 *       revoking a grant = revoke the {@code broadcast} row.</li>
 * </ul>
 * Each write is IDEMPOTENT on an existing active row of the same type (returned unchanged
 * — the partial-unique index is the race backstop).
 */
@Service
public class OwncastBroadcastService {

    private static final Logger log = LoggerFactory.getLogger(OwncastBroadcastService.class);

    private final OwncastGrantRepository repo;
    private final PrincipalDomain principalDomain;

    public OwncastBroadcastService(OwncastGrantRepository repo, PrincipalDomain principalDomain) {
        this.repo = repo;
        this.principalDomain = principalDomain;
    }

    /**
     * Grant {@code userSubject} a PERMANENT may-broadcast override in the actor's brand (or,
     * for a SUPERADMIN, the {@code targetDomain} victim brand).
     *
     * @param userSubject  the Casdoor subject of the user to grant broadcast to
     * @param reason       human-readable reason recorded on the override row (may be null)
     * @param targetDomain the TARGET's brand for a SUPERADMIN cross-brand grant; ignored
     *                     for a scoped ADMIN (issuer-derived)
     * @param actor        the authenticated admin/superadmin performing the grant
     */
    public Mono<OwncastGrant> grant(String userSubject, String reason, String targetDomain,
                                    Authentication actor) {
        return upsertActive(userSubject, OwncastGrant.TYPE_BROADCAST, null, reason, targetDomain,
                actor, "grant");
    }

    /**
     * TIMEOUT {@code userSubject}: a {@code banned} override with a FUTURE expiry — denies
     * broadcast for {@code ttlSeconds}, then auto-restores (the enforcement read stops
     * denying once {@code expires_at <= now}, no write required).
     *
     * @param targetDomain the VICTIM's brand for a SUPERADMIN cross-brand timeout; ignored
     *                     for a scoped ADMIN (issuer-derived)
     */
    public Mono<OwncastGrant> timeout(String userSubject, long ttlSeconds, String reason,
                                      String targetDomain, Authentication actor) {
        Instant expiresAt = Instant.now().plus(Duration.ofSeconds(ttlSeconds));
        return upsertActive(userSubject, OwncastGrant.TYPE_BANNED, expiresAt, reason, targetDomain,
                actor, "timeout");
    }

    /**
     * BAN {@code userSubject}: a PERMANENT {@code banned} override (expires_at NULL) in the
     * actor's brand (or, for a SUPERADMIN, the {@code targetDomain} victim brand).
     *
     * @param targetDomain the VICTIM's brand for a SUPERADMIN cross-brand ban; ignored for
     *                     a scoped ADMIN (issuer-derived)
     */
    public Mono<OwncastGrant> ban(String userSubject, String reason, String targetDomain,
                                  Authentication actor) {
        return upsertActive(userSubject, OwncastGrant.TYPE_BANNED, null, reason, targetDomain,
                actor, "ban");
    }

    /**
     * REVOKE the active override of {@code accessType} for {@code userSubject} in the
     * actor's brand (CAS active->revoked; the row is retained = audit). A no-op (empty)
     * when there is no active override of that type. Restoring broadcast = revoke the
     * {@code banned} row; removing a grant = revoke the {@code broadcast} row.
     */
    public Mono<Void> revoke(String userSubject, String accessType, Authentication actor) {
        String domain = scopeOf(actor);
        // A scoped admin can only resolve (and therefore revoke) a row in their own brand;
        // another brand's active override is invisible, so the revoke is a no-op for them.
        return repo.findActive(userSubject, accessType, domain)
                .flatMap(active -> repo.revoke(active.id())
                        .doOnNext(n -> log.info("[owncast-grant] revoked {} for {} by {} (id={}, rows={})",
                                accessType, userSubject, subject(actor), active.id(), n)))
                .then();
    }

    /** All active overrides VISIBLE to the actor (MANAGE read surface). Scoped admin sees
     *  only their brand; SUPERADMIN sees all. */
    public Flux<OwncastGrant> listActive(Authentication actor) {
        return repo.listActive(scopeOf(actor));
    }

    /** The full history (active + revoked) for a principal VISIBLE to the actor — the
     *  audit read (revoked rows retained). */
    public Flux<OwncastGrant> historyFor(String userSubject, Authentication actor) {
        return repo.historyFor(userSubject, scopeOf(actor));
    }

    // ── helpers ────────────────────────────────────────────────────────

    /**
     * Idempotent insert-active: an existing active row of the same type VISIBLE to the WRITE
     * scope is returned unchanged (a re-grant/re-ban while active is a no-op); otherwise a
     * new active row is stamped with the WRITE brand. The write brand is the actor's own
     * brand for a scoped ADMIN, and the resolved {@code targetDomain} victim brand for a
     * SUPERADMIN (see {@link #writeDomain}).
     */
    private Mono<OwncastGrant> upsertActive(String userSubject, String accessType, Instant expiresAt,
                                            String reason, String targetDomain, Authentication actor,
                                            String verb) {
        String by = subject(actor);
        // Resolve the WRITE brand first (may FAIL CLOSED for a SUPERADMIN cross-brand write
        // with no/unknown targetDomain) — done inside the reactive chain so the failure is an
        // errored Mono, not a synchronous assembly-time throw.
        return writeDomain(actor, targetDomain, verb)
                // The idempotency pre-check + the insert both use the SAME brand the row is
                // stamped with, so a SUPERADMIN re-ban of a brand-X user is a no-op against the
                // brand-X row (not against an unrelated default row the guard never reads).
                .flatMap(domain -> repo.findActive(userSubject, accessType, domain)
                        .doOnNext(existing -> log.info("[owncast-grant] {} {} already active for {} (id={}) — no-op",
                                verb, accessType, userSubject, existing.id()))
                        .switchIfEmpty(Mono.defer(() ->
                                repo.insertActive(userSubject, accessType, expiresAt, reason, by, domain)
                                        .doOnNext(a -> log.info("[owncast-grant] {} created {} for {} "
                                                        + "(id={}, expiresAt={}, domain={})",
                                                verb, accessType, userSubject, a.id(), expiresAt, a.domain())))));
    }

    /**
     * The brand a write must be STAMPED with — so {@link OwncastBroadcastGuard}, which reads
     * back {@code activeFor(subject, victimBrand)}, actually matches it. Returns the brand as
     * a {@link Mono} so a SUPERADMIN's missing/unknown target FAILS CLOSED as an errored Mono
     * (a {@code 400}) rather than a synchronous assembly-time throw.
     *
     * <ul>
     *   <li>A scoped ADMIN ({@link #scopeOf} returns a concrete brand): always their own
     *       issuer-derived brand; the {@code targetDomain} body field is IGNORED so an ADMIN
     *       can never write into another brand.</li>
     *   <li>A SUPERADMIN ({@link #scopeOf} returns {@code null}, the cross-domain actor):
     *       the row must land in the VICTIM's brand, which the actor's null scope cannot
     *       supply — so we resolve the {@code targetDomain} body field against the trusted
     *       {@link systems.hugmesh.commons.security.DomainRegistry}
     *       ({@link PrincipalDomain#resolveKnownDomain}). In multi-issuer mode a SUPERADMIN
     *       MUST name a real victim brand: a missing/unknown target FAILS CLOSED
     *       ({@code 400}) rather than being normalised to {@code default} by
     *       {@link OwncastGrantRepository#insertActive}, which the broadcast guard would
     *       never match against a non-default streamer (the silent no-effect ban this fix
     *       closes). In single-issuer mode every principal is {@code default}, so a
     *       SUPERADMIN write keeps the legacy {@code default} brand (behaviour unchanged).</li>
     * </ul>
     */
    private Mono<String> writeDomain(Authentication actor, String targetDomain, String verb) {
        String scope = scopeOf(actor);
        // Scoped ADMIN: own brand only; the request's targetDomain is inert (no cross-brand write).
        if (scope != null) {
            return Mono.just(scope);
        }
        // SUPERADMIN cross-domain write: in single-issuer mode there is no real victim brand
        // to name, so keep the legacy default (unchanged behaviour).
        if (!principalDomain.isMultiIssuer()) {
            return Mono.just(DomainRegistry.DEFAULT_DOMAIN);
        }
        // Multi-brand: resolve the victim brand from the body against the trusted registry and
        // FAIL CLOSED if it is absent/unknown — a default-stamped ban is silently ineffective.
        String resolved = principalDomain.resolveKnownDomain(targetDomain);
        return resolved != null
                ? Mono.just(resolved)
                : Mono.error(ApiException.badRequest(
                        "a SUPERADMIN " + verb + " must target a known brand via targetDomain"));
    }

    /** The actor's brand — {@code null} for SUPERADMIN (cross-domain), else the
     *  issuer-derived {@code DOMAIN_<x>}; {@code default} for a non-JWT (test) principal.
     *  NEVER a request field. */
    private String scopeOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return principalDomain.forScope(jwt);
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }

    /** The acting principal's Casdoor subject (the granted_by key). */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null) {
            return jwt.getSubject();
        }
        return auth == null || auth.getName() == null ? "@system" : auth.getName();
    }
}
