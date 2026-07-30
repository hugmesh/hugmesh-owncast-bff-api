package systems.hugmesh.owncastbff.access;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.owncastbff.security.PrincipalDomain;
import systems.hugmesh.commons.security.Roles;
import systems.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.List;

/**
 * THE LOAD-BEARING enforcement of the broadcast grant/timeout/ban overlay: it resolves
 * whether a request principal may BROADCAST by reading the DYNAMIC {@code owncast_grant}
 * desired-state and applying the precedence rule. The {@code WikiAccessGuard} twin — with
 * ONE deliberate DELTA: broadcast is <b>DEFAULT-DENY and GRANT-ONLY</b>. Where wiki read
 * has a static role floor (ADMIN | SUPERADMIN | (MOD AND WIKI)) that the guard OR-s in,
 * broadcast has <b>NO role-qualifies path at all</b> — no role confers broadcast; an
 * active {@link OwncastGrant#TYPE_BROADCAST} grant is the ONLY way in (besides the
 * SUPERADMIN infra exemption).
 *
 * <p>A static {@code @PreAuthorize} on the controller CANNOT consult the DB for a
 * per-principal grant or ban, so — exactly as wiki-bff / admin-bff enforce their overlays
 * at request time rather than leaving them inert — this guard is invoked programmatically
 * by the broadcast-affecting endpoints, loads the principal's {@code owncast_grant} rows
 * for their brand, and decides:
 *
 * <pre>
 *   BROADCAST ALLOWED  ==  SUPERADMIN (infra, exempt — no DB read)
 *                          OR ( an ACTIVE non-expired BROADCAST grant for this user+domain
 *                               AND NOT an ACTIVE non-expired BAN/TIMEOUT for this user+domain )
 * </pre>
 *
 * <p>PRECEDENCE — the load-bearing rule:
 * <ul>
 *   <li>DEFAULT-DENY: no grant ⇒ cannot broadcast (no role ever substitutes for the grant);</li>
 *   <li>an ACTIVE non-expired BAN/TIMEOUT DENIES even a principal who holds an active
 *       BROADCAST grant (<b>ban &gt; grant</b> — the ban wins);</li>
 *   <li>SUPERADMIN is UNAFFECTED by a ban (infra control plane) — checked FIRST, before
 *       any DB read;</li>
 *   <li>an EXPIRED timeout auto-restores: {@link OwncastGrant#isEffectiveAt} treats a past
 *       {@code expires_at} as no-longer-active, so the row stops denying WITHOUT a write.</li>
 * </ul>
 */
@Component
public class OwncastBroadcastGuard {

    private final OwncastGrantRepository repo;
    private final PrincipalDomain principalDomain;

    public OwncastBroadcastGuard(OwncastGrantRepository repo, PrincipalDomain principalDomain) {
        this.repo = repo;
        this.principalDomain = principalDomain;
    }

    /**
     * Enforce broadcast access for the request principal, applying the DEFAULT-DENY overlay
     * precedence. Completes (passes through the empty Mono) when broadcast is allowed; errors
     * with a 403 {@link ApiException} when an active ban/timeout denies it OR when there is no
     * active broadcast grant. Wrap a broadcast-affecting endpoint as
     * {@code guard.assertCanBroadcast(auth).then(...)}.
     */
    public Mono<Void> assertCanBroadcast(Authentication auth) {
        // SUPERADMIN is the infra control plane — exempt from the overlay (never banned
        // out, and may broadcast without a grant), resolved with NO DB read.
        if (isSuperadmin(auth)) {
            return Mono.empty();
        }
        String domain = scopeOf(auth);
        String subject = subject(auth);
        Instant now = Instant.now();

        // Load the principal's ACTIVE overrides for THEIR brand and apply the precedence.
        return repo.activeFor(subject, domain)
                // An expired timeout auto-restores: rows past their expires_at are ignored.
                .filter(a -> a.isEffectiveAt(now))
                // Collect all effective rows then enforce ban > grant > default-deny precedence.
                .collectList()
                .flatMap(OwncastBroadcastGuard::enforceBroadcastPrecedence);
    }

    /**
     * Enforce ban &gt; grant &gt; default-deny precedence over the caller's effective grant rows.
     * Returns an empty Mono (allowed) when a broadcast grant is active and no ban is present;
     * errors with 403 when banned or when no grant exists (default-deny).
     */
    private static Mono<Void> enforceBroadcastPrecedence(List<OwncastGrant> rows) {
        boolean banned = rows.stream()
                .anyMatch(a -> OwncastGrant.TYPE_BANNED.equals(a.accessType()));
        boolean granted = rows.stream()
                .anyMatch(a -> OwncastGrant.TYPE_BROADCAST.equals(a.accessType()));
        // PRECEDENCE: an active ban/timeout denies even a grantee (ban > grant).
        if (banned) {
            return Mono.error(ApiException.forbidden(
                    "broadcast is banned for this principal in this brand"));
        }
        // DEFAULT-DENY + GRANT-ONLY: allowed ONLY when an active broadcast grant
        // exists — NO role substitutes for it.
        if (granted) {
            return Mono.empty();
        }
        return Mono.error(ApiException.forbidden(
                "broadcast requires an active grant (default-deny)"));
    }

    /** SUPERADMIN read from either the JWT roles claim (runtime shape) or the converted
     *  authorities (test/authorities-only shape). */
    private boolean isSuperadmin(Authentication auth) {
        if (auth == null) return false;
        if (auth.getPrincipal() instanceof Jwt jwt && Roles.isSuperadmin(jwt)) {
            return true;
        }
        return Roles.isSuperadmin(auth.getAuthorities());
    }

    /** The caller's brand — derived SERVER-SIDE from the validated JWT issuer
     *  ({@link PrincipalDomain}); the {@code default} domain for a non-JWT principal
     *  (test/single-tenant). NEVER a request field. SUPERADMIN never reaches this (it is
     *  short-circuited above), so the {@code null} bypass is never used by the guard. */
    private String scopeOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String d = principalDomain.forScope(jwt);
            return d == null ? DomainRegistry.DEFAULT_DOMAIN : d;
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }

    /** The acting principal's Casdoor subject — the key the overlay targets. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null) {
            return jwt.getSubject();
        }
        return auth == null || auth.getName() == null ? "" : auth.getName();
    }
}
