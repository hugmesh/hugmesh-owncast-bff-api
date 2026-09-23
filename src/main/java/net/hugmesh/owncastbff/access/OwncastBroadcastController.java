package net.hugmesh.owncastbff.access;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The broadcast grant / timeout / ban OVERLAY surface — the write side of the
 * {@code owncast_grant} desired-state that {@link OwncastBroadcastGuard} enforces
 * (DEFAULT-DENY) on the broadcast path. Role model copied from the wiki-bff
 * {@code WikiAccessController}.
 *
 * <p><b>ROLE MODEL.</b> {@code ROLE_OWNCAST} is the base service role (sibling of
 * {@code ROLE_WIKI} / {@code ROLE_FORUM}) — the gateway route-access floor for the
 * owncast surface; it does NOT by itself confer broadcast (broadcast is grant-only,
 * enforced by {@link OwncastBroadcastGuard}). The governance write actions are gated
 * one tier up:
 * <ul>
 *   <li>grant / timeout / ban / restore (revoke) — {@link #OWNCAST_GOVERN}
 *       (ADMIN | SUPERADMIN). Mounted under {@code /bff/owncast/admin/access/**} so the
 *       SecurityConfig path gate is ADMIN|SUPERADMIN end-to-end AND the method-level
 *       {@code @PreAuthorize} re-checks (defence in depth). An ADMIN governs only WITHIN
 *       their own brand (server-derived domain); SUPERADMIN is cross-domain.</li>
 *   <li>list-all / history (manage-all) — {@link #OWNCAST_MANAGE} (SUPERADMIN), mounted
 *       under {@code /bff/owncast/superadmin/access} so the path gate is SUPERADMIN.</li>
 * </ul>
 * Every write is DOMAIN-SCOPED in the service; {@code state=revoked} rows are RETAINED
 * (audit), never hard-deleted.
 */
@Tag(name = "Owncast Broadcast Access", description = "Owncast broadcast grant/timeout/ban "
        + "overlay (owncast_grant): grant/timeout/ban/restore (OWNCAST_GOVERN), list-all/history "
        + "(OWNCAST_MANAGE). Domain-scoped; broadcast is DEFAULT-DENY, enforced at request time "
        + "by OwncastBroadcastGuard (an active grant AND NOT an active ban, SUPERADMIN exempt).")
@RestController
@RequestMapping("/bff/owncast")
@Validated
public class OwncastBroadcastController {

    /** OWNCAST_GOVERN — grant/timeout/ban/restore may-broadcast: ADMIN or SUPERADMIN.
     *  An admin decides which of their domain's users may broadcast on a UI. */
    public static final String OWNCAST_GOVERN = "hasRole('ADMIN') or hasRole('SUPERADMIN')";

    /** OWNCAST_MANAGE — manage-all of the owncast governance solution: SUPERADMIN only
     *  (list-all + history here; the per-domain service-enable and the provisioning
     *  effector are still 🔭 planned — see the README Roadmap). */
    public static final String OWNCAST_MANAGE = "hasRole('SUPERADMIN')";

    private final OwncastBroadcastService access;

    public OwncastBroadcastController(OwncastBroadcastService access) {
        this.access = access;
    }

    // ── grant / timeout / ban / restore (OWNCAST_GOVERN) ───────────────

    @Operation(summary = "GRANT a USER permanent may-broadcast access (an active owncast_grant "
            + "broadcast override) — the ONLY way to confer broadcast (default-deny). "
            + "ADMIN/SUPERADMIN, own-brand.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Broadcast grant created (or returned unchanged if already active)"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field, or a SUPERADMIN write in multi-brand mode without a known targetDomain (fail-closed)", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_GOVERN)
    @PostMapping("/admin/access/grant")
    public Mono<ResponseEntity<OwncastAccessDto.Access>> grant(
            @Valid @RequestBody OwncastAccessDto.GrantOrBan body, Authentication auth) {
        return access.grant(body.userSubject(), body.reason(), body.targetDomain(), auth)
                .map(a -> ResponseEntity.ok(OwncastAccessDto.Access.of(a)));
    }

    @Operation(summary = "TIMEOUT a USER from broadcast for a bounded window (an active banned "
            + "override with a future expires_at; auto-restores on expiry). ADMIN/SUPERADMIN, "
            + "own-brand.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Broadcast timeout created (or returned unchanged if already active)"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field, or a SUPERADMIN write in multi-brand mode without a known targetDomain (fail-closed)", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_GOVERN)
    @PostMapping("/admin/access/timeout")
    public Mono<ResponseEntity<OwncastAccessDto.Access>> timeout(
            @Valid @RequestBody OwncastAccessDto.Timeout body, Authentication auth) {
        return access.timeout(body.userSubject(), body.ttlSeconds(), body.reason(),
                        body.targetDomain(), auth)
                .map(a -> ResponseEntity.ok(OwncastAccessDto.Access.of(a)));
    }

    @Operation(summary = "BAN a USER from broadcast permanently (an active banned override, "
            + "expires_at NULL). Denies even an active grantee (ban>grant). ADMIN/SUPERADMIN, "
            + "own-brand.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Broadcast ban created (or returned unchanged if already active)"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field, or a SUPERADMIN write in multi-brand mode without a known targetDomain (fail-closed)", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_GOVERN)
    @PostMapping("/admin/access/ban")
    public Mono<ResponseEntity<OwncastAccessDto.Access>> ban(
            @Valid @RequestBody OwncastAccessDto.GrantOrBan body, Authentication auth) {
        return access.ban(body.userSubject(), body.reason(), body.targetDomain(), auth)
                .map(a -> ResponseEntity.ok(OwncastAccessDto.Access.of(a)));
    }

    @Operation(summary = "RESTORE/REVOKE: lift the active override of a type for a user "
            + "(CAS active->revoked; the row is retained = audit). accessType = broadcast|banned: "
            + "revoke 'banned' to restore broadcast; revoke 'broadcast' to remove a grant. "
            + "ADMIN/SUPERADMIN, own-brand.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Override revoked (row retained for audit)"),
            @ApiResponse(responseCode = "400", description = "accessType must be 'broadcast' or 'banned'", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_GOVERN)
    @DeleteMapping("/admin/access/{accessType}/{userSubject}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @PathVariable String accessType, @PathVariable String userSubject, Authentication auth) {
        String type = switch (accessType) {
            case OwncastGrant.TYPE_BROADCAST -> OwncastGrant.TYPE_BROADCAST;
            case OwncastGrant.TYPE_BANNED    -> OwncastGrant.TYPE_BANNED;
            default                          -> null;
        };
        if (type == null) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "error", "accessType must be 'broadcast' or 'banned'")));
        }
        return access.revoke(userSubject, type, auth)
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of(
                        "state", "revoked", "accessType", type, "userSubject", userSubject)));
    }

    // ── manage-all (OWNCAST_MANAGE) ────────────────────────────────────

    @Operation(summary = "List all ACTIVE owncast_grant overrides (scoped to the caller's "
            + "brand; SUPERADMIN sees all). SUPERADMIN.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Active overrides list returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_MANAGE)
    @GetMapping("/superadmin/access")
    public Mono<OwncastAccessDto.AccessList> listActive(Authentication auth) {
        return access.listActive(auth).map(OwncastAccessDto.Access::of)
                .collectList().map(OwncastAccessDto.AccessList::new);
    }

    @Operation(summary = "The full grant/timeout/ban HISTORY (active + revoked = audit) for "
            + "a principal (scoped to the caller's brand; SUPERADMIN sees all). SUPERADMIN.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Full history (active + revoked) returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_MANAGE)
    @GetMapping("/superadmin/access/{userSubject}/history")
    public Mono<OwncastAccessDto.AccessList> history(@PathVariable String userSubject, Authentication auth) {
        return access.historyFor(userSubject, auth).map(OwncastAccessDto.Access::of)
                .collectList().map(OwncastAccessDto.AccessList::new);
    }
}
