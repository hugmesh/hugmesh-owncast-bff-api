package net.hugmesh.owncastbff.stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.owncastbff.access.OwncastBroadcastGuard;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.owncastbff.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

/**
 * The OWNER-controlled write/read surface for {@code owncast_stream} — a streamer's OWN
 * stream descriptor + self-visibility flag. The sibling of {@code OwncastBroadcastService}
 * (the ADMIN-controlled governance overlay): here the acting principal IS the streamer, and
 * EVERY operation targets THEIR OWN stream in THEIR OWN brand. Mirrors how
 * {@code OwncastBroadcastService} derives the principal's identity:
 *
 * <ul>
 *   <li>the OWNER is {@code jwt.getSubject()} — never a request field, so a user can only
 *       ever read/modify their own stream;</li>
 *   <li>the DOMAIN is derived SERVER-SIDE from the validated issuer
 *       ({@link PrincipalDomain#forScope}) — never a request field, so a stream in brand X
 *       is invisible to brand Y.</li>
 * </ul>
 *
 * <p><b>SECURITY-CRITICAL GATE (the load-bearing rule of this PR).</b> A stream may only be
 * set/kept {@code visibility=PUBLIC} if the OWNER currently holds an active BROADCAST grant.
 * A flip to PUBLIC ({@link #setVisibility}) calls {@link OwncastBroadcastGuard#assertCanBroadcast}
 * FIRST and propagates its 403 on deny — so a user WITHOUT a broadcast grant (or a banned user)
 * can have an INTERNAL stream but CANNOT make it public, and SUPERADMIN is exempt per the guard.
 * Going to (or staying) {@code internal} is always allowed (no grant needed). A first
 * {@link #upsertMyStream} is born INTERNAL (fail-closed — never public), so it needs no gate;
 * the streamer makes it public via the gated {@link #setVisibility}.
 *
 * <p>FAIL-CLOSED: a non-JWT / subject-less principal cannot be resolved to an owner, so the
 * stream operations reject it (401) rather than acting under an ambiguous identity.
 */
@Service
public class OwncastStreamService {

    private static final Logger log = LoggerFactory.getLogger(OwncastStreamService.class);

    private final OwncastStreamRepository repo;
    private final OwncastBroadcastGuard broadcastGuard;
    private final PrincipalDomain principalDomain;
    private final OwncastPlaybackUrlResolver playbackUrls;

    public OwncastStreamService(OwncastStreamRepository repo, OwncastBroadcastGuard broadcastGuard,
                                PrincipalDomain principalDomain, OwncastPlaybackUrlResolver playbackUrls) {
        this.repo = repo;
        this.broadcastGuard = broadcastGuard;
        this.principalDomain = principalDomain;
        this.playbackUrls = playbackUrls;
    }

    /**
     * The acting streamer's OWN stream (owner == jwt.sub, brand server-derived), or empty if
     * they have none yet, with {@code playbackUrl} populated ONLY when the caller is PERMITTED
     * to view the stream.
     *
     * <p><b>VIEW GATE (no URL leak).</b> The streamer always sees their own stream METADATA,
     * but the per-instance HLS {@code playbackUrl} is the media endpoint — it is filled in ONLY
     * when the SAME broadcast/visibility gate that governs going public
     * ({@link OwncastBroadcastGuard#assertCanBroadcast}) ALLOWS this caller in their brand:
     * an active broadcast grant AND not banned, SUPERADMIN exempt, domain-scoped. A caller who
     * is not permitted (no grant / banned / cross-tenant) gets the stream with a {@code null}
     * {@code playbackUrl} — the URL is never leaked. {@link #fillPlaybackUrl} swallows the
     * guard's 403 into "no URL" so a denied view degrades to a null field rather than failing
     * the metadata read.
     */
    public Mono<OwncastStream> getMyStream(Authentication actor) {
        return requireOwner(actor)
                .flatMap(owner -> repo.findForOwner(owner, scopeOf(actor)))
                .flatMap(stream -> fillPlaybackUrl(actor, stream));
    }

    /**
     * Populate {@code playbackUrl} on {@code stream} ONLY for a caller PERMITTED to view it,
     * reusing the existing broadcast/visibility gate. When the gate ALLOWS, the URL is resolved
     * from the (inactive-by-default) template for the stream's OWN brand + owner. When the gate
     * DENIES (its 403) the stream is returned UNCHANGED ({@code playbackUrl} stays {@code null})
     * — so the media endpoint is never leaked to an unauthorized or cross-tenant caller.
     */
    private Mono<OwncastStream> fillPlaybackUrl(Authentication actor, OwncastStream stream) {
        return broadcastGuard.assertCanBroadcast(actor)
                .thenReturn(stream.withPlaybackUrl(
                        playbackUrls.resolve(stream.domain(), stream.userSubject())))
                // ONLY a 403 (the guard's view-deny) degrades to "no URL"; any other error
                // (e.g. a 401) still propagates so we never mask an unexpected failure.
                .onErrorResume(e -> e instanceof ApiException api
                        && api.status() == HttpStatus.FORBIDDEN
                        ? Mono.just(stream) : Mono.error(e));
    }

    /**
     * Create-or-update the acting streamer's OWN stream metadata ({@code title} /
     * {@code description}), leaving visibility unchanged on an existing stream. A FIRST
     * upsert (no existing row) creates the stream {@code visibility=internal} (fail-closed —
     * a new stream is never born public; the streamer flips it via {@link #setVisibility},
     * which enforces the broadcast-grant gate). Owner + brand are server-derived.
     */
    public Mono<OwncastStream> upsertMyStream(Authentication actor, String title, String description) {
        String domain = scopeOf(actor);
        return requireOwner(actor).flatMap(owner -> repo.findForOwner(owner, domain)
                .flatMap(existing -> repo.updateMeta(owner, title, description, domain)
                        .doOnNext(n -> log.info("[owncast-stream] {} updated own stream meta "
                                + "(id={}, domain={}, rows={})", owner, existing.id(), domain, n))
                        .then(repo.findForOwner(owner, domain)))
                .switchIfEmpty(Mono.defer(() ->
                        repo.insert(owner, title, description, OwncastStream.VISIBILITY_INTERNAL, domain)
                                .doOnNext(s -> log.info("[owncast-stream] {} created own stream "
                                        + "(id={}, domain={}, visibility=internal)",
                                        owner, s.id(), s.domain())))));
    }

    /**
     * Flip the acting streamer's OWN stream visibility to {@code public} or {@code internal}.
     *
     * <p><b>THE SECURITY-CRITICAL GATE.</b> A flip to (or keeping) PUBLIC is allowed ONLY when
     * the owner currently holds an active broadcast grant: {@link OwncastBroadcastGuard#assertCanBroadcast}
     * is consulted FIRST and its 403 is propagated on deny (a user without a grant — or a banned
     * user — gets 403; SUPERADMIN is exempt per the guard). A flip to INTERNAL needs no grant.
     * The stream must already exist (404 otherwise) — the streamer upserts metadata first.
     */
    public Mono<OwncastStream> setVisibility(Authentication actor, String requestedVisibility) {
        String domain = scopeOf(actor);
        String visibility = OwncastStream.normalizeVisibility(requestedVisibility);
        if (visibility == null) {
            return Mono.error(ApiException.badRequest("visibility must be 'public' or 'internal'"));
        }
        // THE GATE: a PUBLIC flip requires an active broadcast grant for the owner (the guard
        // is default-deny + ban>grant, SUPERADMIN exempt). An INTERNAL flip is always allowed.
        Mono<Void> gate = OwncastStream.VISIBILITY_PUBLIC.equals(visibility)
                ? broadcastGuard.assertCanBroadcast(actor)
                : Mono.empty();
        return requireOwner(actor).flatMap(owner -> gate.then(repo.setVisibility(owner, visibility, domain)
                .flatMap(rows -> rows == 0
                        ? Mono.error(ApiException.notFound("no stream for this streamer"))
                        : repo.findForOwner(owner, domain))
                .doOnNext(s -> log.info("[owncast-stream] {} set own stream visibility={} (domain={})",
                        owner, visibility, domain))));
    }

    // ── helpers (owner + domain derived server-side; fail-closed) ──────────

    /** The acting streamer's Casdoor subject — the OWNER key, as a reactive signal so a
     *  failure surfaces as a {@link Mono#error} (not an eager throw) in the stream. FAIL-CLOSED:
     *  a non-JWT / subject-less principal cannot own a stream, so it is rejected (401) rather
     *  than acting under an ambiguous identity. NEVER a request field. */
    private static Mono<String> requireOwner(Authentication actor) {
        if (actor != null && actor.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null
                && !jwt.getSubject().isBlank()) {
            return Mono.just(jwt.getSubject());
        }
        return Mono.error(ApiException.unauthorized("an authenticated streamer subject is required"));
    }

    /** The acting streamer's brand — the issuer-derived {@code DOMAIN_<x>}; the platform
     *  {@code default} domain for a non-JWT (test) principal or a SUPERADMIN unscoped value
     *  so an owned row always carries a concrete brand. NEVER a request field. */
    private String scopeOf(Authentication actor) {
        if (actor != null && actor.getPrincipal() instanceof Jwt jwt) {
            String d = principalDomain.forScope(jwt);
            return d == null ? DomainRegistry.DEFAULT_DOMAIN : d;
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }
}
