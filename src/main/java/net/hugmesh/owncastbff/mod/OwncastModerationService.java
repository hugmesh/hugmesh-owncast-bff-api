package net.hugmesh.owncastbff.mod;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.owncastbff.access.OwncastGrant;
import net.hugmesh.owncastbff.access.OwncastGrantRepository;
import net.hugmesh.owncastbff.security.PrincipalDomain;
import net.hugmesh.owncastbff.stream.OwncastStream;
import net.hugmesh.owncastbff.stream.OwncastStreamRepository;
import net.hugmesh.commons.web.ApiException;

/**
 * The MODERATION write/read surface — the service behind {@code /bff/owncast/mod/**}.
 * A moderator (MOD | ADMIN | SUPERADMIN) of brand X can ENUMERATE brand X's streams and force
 * a stream internal (hide), KILL a stream (ban its owner's broadcast + hide), or RESTORE (lift
 * the ban). It is the kill/hide/ban/restore-ONLY sibling of the ADMIN-controlled
 * {@code OwncastBroadcastService} (which additionally GRANTs/GOVERNs) and the OWNER-controlled
 * {@code OwncastStreamService} (which acts on the caller's OWN stream).
 *
 * <p><b>AUTHORITY MODEL — the privilege boundary.</b> The authority for every action here is the
 * MOD role (path-gated) + a DOMAIN match — NOT ownership. A moderator therefore acts on ANOTHER
 * user's stream (the TARGET {@code ownerSubject}), unlike the owner service where the subject is
 * always {@code jwt.sub}. CRITICALLY, this service exposes ONLY kill/hide/ban/restore: it NEVER
 * grants broadcast and never reaches the admin/superadmin govern surface — a MOD is confined to
 * the moderation verbs.
 *
 * <p><b>BAN/RESTORE REUSE owncast_grant — NOT a parallel mechanism.</b> A kill/ban writes an
 * {@code owncast_grant(access_type=banned, state=active)} via the SAME desired-state
 * insert-active path the admin ban uses (audit-preserving, partial-unique on active, never
 * hard-delete). The EXISTING {@code OwncastBroadcastGuard} (ban&gt;grant precedence) then
 * immediately denies the owner's public broadcast flip on the next request. A restore CASes that
 * active ban active-&gt;revoked (the row is RETAINED = audit); it does NOT auto-republish (the
 * owner re-chooses visibility).
 *
 * <p><b>DOMAIN SCOPING (critical).</b> The moderator domain is ALWAYS derived SERVER-SIDE from
 * the validated JWT issuer ({@link PrincipalDomain#forScope}) — NEVER a request field. Every
 * list/hide/ban/restore is scoped to {@code (moderatorDomain, ownerSubject)}: a mod in brand X
 * acting on owner S affects ONLY (X,S); if S also streams in brand Y, (Y,S) is untouched. There
 * is NO superadmin null-domain / all-brands bypass on the moderation surface — everyone is
 * domain-pinned (consistent with the rest of owncast-bff's domain-scoped endpoints).
 *
 * <p><b>FAIL-CLOSED.</b> A non-JWT / blank-subject principal cannot be resolved to a moderator,
 * so every operation rejects it (401) rather than acting under an ambiguous identity.
 */
@Service
public class OwncastModerationService {

    private static final Logger log = LoggerFactory.getLogger(OwncastModerationService.class);

    private final OwncastStreamRepository streamRepo;
    private final OwncastGrantRepository grantRepo;
    private final OwncastModerationAuditRepository auditRepo;
    private final PrincipalDomain principalDomain;

    public OwncastModerationService(OwncastStreamRepository streamRepo,
                                    OwncastGrantRepository grantRepo,
                                    OwncastModerationAuditRepository auditRepo,
                                    PrincipalDomain principalDomain) {
        this.streamRepo = streamRepo;
        this.grantRepo = grantRepo;
        this.auditRepo = auditRepo;
        this.principalDomain = principalDomain;
    }

    /**
     * The ACTIVE streams in the MODERATOR's brand, each annotated with whether the owner
     * currently holds an active broadcast BAN ({@code owncast_grant} banned, active). Domain
     * scoped: a moderator of brand X never sees brand Y's streams.
     */
    public Flux<OwncastModerationDto.StreamRow> listStreams(Authentication actor) {
        return requireModerator(actor).flatMapMany(mod ->
                streamRepo.listInDomain(domain(actor))
                        .flatMap(s -> grantRepo.findActive(s.userSubject(), OwncastGrant.TYPE_BANNED, domain(actor))
                                .map(ban -> true)
                                .defaultIfEmpty(false)
                                .map(banned -> new OwncastModerationDto.StreamRow(
                                        s.userSubject(), s.domain(), s.title(), s.visibility(), banned))));
    }

    /**
     * HIDE: force the TARGET owner's stream {@code visibility=internal} in the moderator's brand
     * (moderator-initiated — the authority is the MOD role + domain match, NOT ownership). 404
     * when the target has no stream in this brand. Writes a {@code hide} audit row.
     */
    public Mono<OwncastModerationDto.ActionResult> hide(Authentication actor, String ownerSubject, String reason) {
        String domain = domain(actor);
        // Resolve the acting moderator's subject then execute the hide in their brand.
        return requireModerator(actor)
                .flatMap(mod -> performHide(mod, domain, ownerSubject, reason));
    }

    /**
     * Execute the hide action: force the target stream internal, write an audit row, then
     * report the result annotated with the owner's current active-ban state.
     */
    private Mono<OwncastModerationDto.ActionResult> performHide(
            String mod, String domain, String ownerSubject, String reason) {
        // Set the target stream to internal — 404 if the owner has no stream in this brand.
        return streamRepo.setVisibility(ownerSubject, OwncastStream.VISIBILITY_INTERNAL, domain)
                // 404 when the target has no stream; otherwise persist the hide audit row.
                .flatMap(rows -> rows == 0
                        ? Mono.error(ApiException.notFound("no stream for this owner in this brand"))
                        : audit(domain, mod, ownerSubject, OwncastModerationAudit.ACTION_HIDE, reason)
                                .thenReturn(rows))
                // Annotate the result with whether the owner is currently banned in this brand.
                .flatMap(rows -> activeBan(ownerSubject, domain).map(banned ->
                        new OwncastModerationDto.ActionResult(OwncastModerationAudit.ACTION_HIDE,
                                ownerSubject, domain, OwncastStream.VISIBILITY_INTERNAL, banned)))
                .doOnSuccess(r -> log.info("[owncast-mod] {} HID stream of {} (domain={})",
                        mod, ownerSubject, domain));
    }

    /**
     * KILL ("ban"): write an {@code owncast_grant(access_type=banned, state=active)} for the
     * target via the SAME desired-state insert-active path the admin ban uses (idempotent on an
     * existing active ban; audit-preserving; partial-unique on active; never hard-delete) — so
     * the EXISTING {@code OwncastBroadcastGuard} (ban&gt;grant) immediately blocks the owner's
     * public broadcast. ALSO forces the stream internal (the hide half of a kill). Writes a
     * {@code kill} audit row. Domain scoped to the moderator's brand.
     */
    public Mono<OwncastModerationDto.ActionResult> ban(Authentication actor, String ownerSubject, String reason) {
        String domain = domain(actor);
        // Resolve the acting moderator's subject then execute the kill in their brand.
        return requireModerator(actor)
                .flatMap(mod -> performBan(mod, domain, ownerSubject, reason));
    }

    /**
     * Execute the kill (ban + hide) action: upsert an active banned grant, force the stream
     * internal, write a kill audit row, and return the result with banned=true.
     */
    private Mono<OwncastModerationDto.ActionResult> performBan(
            String mod, String domain, String ownerSubject, String reason) {
        // Reuse owncast_grant(banned) — same desired-state write as the admin ban: idempotent
        // on an existing active ban; otherwise stamps a new permanent active ban in this brand.
        return upsertActiveBan(ownerSubject, mod, domain, reason)
                // Force the stream internal (kill = ban + hide).
                .then(streamRepo.setVisibility(ownerSubject, OwncastStream.VISIBILITY_INTERNAL, domain))
                // Persist the kill audit row.
                .then(audit(domain, mod, ownerSubject, OwncastModerationAudit.ACTION_KILL, reason))
                .thenReturn(new OwncastModerationDto.ActionResult(OwncastModerationAudit.ACTION_KILL,
                        ownerSubject, domain, OwncastStream.VISIBILITY_INTERNAL, true))
                .doOnSuccess(r -> log.info("[owncast-mod] {} KILLED (banned+hid) {} (domain={})",
                        mod, ownerSubject, domain));
    }

    /**
     * RESTORE: CAS the TARGET's active broadcast ban active-&gt;revoked in the moderator's brand
     * (the row is RETAINED = audit; a no-op when there is no active ban). It does NOT
     * auto-republish — the owner re-chooses visibility — so the stream is left as-is (internal).
     * Writes a {@code restore} audit row.
     */
    public Mono<OwncastModerationDto.ActionResult> restore(Authentication actor, String ownerSubject, String reason) {
        String domain = domain(actor);
        // Resolve the acting moderator's subject then execute the restore in their brand.
        return requireModerator(actor)
                .flatMap(mod -> performRestore(mod, domain, ownerSubject, reason));
    }

    /**
     * Execute the restore action: revoke the target's active ban in this brand (if any),
     * write a restore audit row, and report the stream's current visibility (unchanged — no
     * auto-republish after a restore).
     */
    private Mono<OwncastModerationDto.ActionResult> performRestore(
            String mod, String domain, String ownerSubject, String reason) {
        // A scoped moderator can only revoke a ban visible in THEIR brand; another brand's
        // active ban is invisible, so the restore is a no-op for those rows.
        return grantRepo.findActive(ownerSubject, OwncastGrant.TYPE_BANNED, domain)
                // Revoke each active ban row found in this brand (audit row is retained).
                .flatMap(active -> grantRepo.revoke(active.id()))
                // Persist the restore audit row.
                .then(audit(domain, mod, ownerSubject, OwncastModerationAudit.ACTION_RESTORE, reason))
                // Visibility is UNCHANGED after restore (no auto-republish) — report current state.
                .then(currentVisibility(ownerSubject, domain))
                .map(vis -> new OwncastModerationDto.ActionResult(OwncastModerationAudit.ACTION_RESTORE,
                        ownerSubject, domain, vis, false))
                .doOnSuccess(r -> log.info("[owncast-mod] {} RESTORED {} (lifted ban; domain={})",
                        mod, ownerSubject, domain));
    }

    // ── helpers (domain + moderator derived server-side; fail-closed) ──────────

    /** Idempotent insert-active of a {@code banned} row in the moderator's brand: an existing
     *  active ban VISIBLE to the brand is returned unchanged (a re-kill while active is a no-op);
     *  otherwise a new permanent active ban (expires_at NULL) is stamped with the brand. Mirrors
     *  the admin ban's desired-state CAS write style. */
    private Mono<OwncastGrant> upsertActiveBan(String ownerSubject, String mod, String domain, String reason) {
        return grantRepo.findActive(ownerSubject, OwncastGrant.TYPE_BANNED, domain)
                .switchIfEmpty(Mono.defer(() -> grantRepo.insertActive(
                        ownerSubject, OwncastGrant.TYPE_BANNED, null, reason, mod, domain)));
    }

    /** Does the target currently hold an active broadcast ban in this brand? */
    private Mono<Boolean> activeBan(String ownerSubject, String domain) {
        return grantRepo.findActive(ownerSubject, OwncastGrant.TYPE_BANNED, domain)
                .map(b -> true).defaultIfEmpty(false);
    }

    /** The target stream's current visibility in the brand, or {@code internal} (fail-closed)
     *  when the target has no stream. */
    private Mono<String> currentVisibility(String ownerSubject, String domain) {
        return streamRepo.findForOwner(ownerSubject, domain)
                .map(OwncastStream::visibility)
                .defaultIfEmpty(OwncastStream.VISIBILITY_INTERNAL);
    }

    private Mono<OwncastModerationAudit> audit(String domain, String actor, String target,
                                               String action, String reason) {
        return auditRepo.insert(domain, actor, target, action, reason);
    }

    /**
     * The acting moderator's Casdoor subject — as a reactive signal so a failure surfaces as a
     * {@link Mono#error} (not an eager throw). FAIL-CLOSED: a non-JWT / subject-less principal
     * cannot be a moderator, so it is rejected (401) rather than acting under an ambiguous
     * identity. NEVER a request field. (The MOD|ADMIN|SUPERADMIN role gate is enforced by the
     * SecurityConfig path matcher + the controller @PreAuthorize ABOVE this — here we only need a
     * concrete subject to attribute the action.)
     */
    private static Mono<String> requireModerator(Authentication actor) {
        if (actor != null && actor.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null
                && !jwt.getSubject().isBlank()) {
            return Mono.just(jwt.getSubject());
        }
        return Mono.error(ApiException.unauthorized("an authenticated moderator subject is required"));
    }

    /**
     * The MODERATOR's brand — derived SERVER-SIDE from the validated issuer
     * ({@link PrincipalDomain#forScope}). The moderation surface domain-pins EVERYONE: there is
     * NO superadmin null-domain bypass here, so a {@code null}/blank scope (a SUPERADMIN
     * cross-domain value, or an unresolved issuer) is pinned to the platform {@code default}
     * domain — a SUPERADMIN moderates within {@code default}, never across all brands. NEVER a
     * request field.
     */
    private String domain(Authentication actor) {
        if (actor != null && actor.getPrincipal() instanceof Jwt jwt) {
            String d = principalDomain.forScope(jwt);
            return (d == null || d.isBlank()) ? DomainRegistry.DEFAULT_DOMAIN : d;
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }
}
