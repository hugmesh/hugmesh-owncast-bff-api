package net.hugmesh.owncastbff.mod;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * The MODERATION surface — {@code /bff/owncast/mod/**}. Fills the gap the owncast-ui Moderation
 * view surfaced (it rendered an empty-state because no moderation endpoint existed). A moderator
 * (MOD | ADMIN | SUPERADMIN) ENUMERATES their brand's streams and acts on a TARGET owner:
 * hide (force internal), kill/ban (write {@code owncast_grant(banned)} + hide), restore (lift
 * the ban). The moderator's BRAND and IDENTITY are derived SERVER-SIDE from the validated JWT
 * by {@link OwncastModerationService} — never a request field — and every action is scoped to
 * {@code (moderatorDomain, ownerSubject)}.
 *
 * <p><b>ROLE MODEL — the privilege boundary.</b> Mounted under {@code /bff/owncast/mod/**}, which
 * the SecurityConfig path gate restricts to {@code MOD | ADMIN | SUPERADMIN} (declared BEFORE the
 * generic {@code /bff/owncast/**} authenticated floor so this prefix wins). The method-level
 * {@link #OWNCAST_MODERATE} {@code @PreAuthorize} re-checks (defence in depth). This controller
 * exposes ONLY kill/hide/ban/restore — it does NOT grant broadcast and does NOT reach the admin
 * {@code /bff/owncast/admin/**} govern surface or the superadmin surface, so a MOD is confined to
 * the moderation verbs (the admin/superadmin prefixes are separate controllers under
 * separate, higher path gates).
 *
 * <p>The ban/restore actions REUSE {@code owncast_grant(access_type=banned)} (NOT a parallel ban
 * mechanism); the existing {@code OwncastBroadcastGuard} (ban&gt;grant) then denies the owner's
 * public broadcast flip. The {@code state=revoked} rows are RETAINED (audit), never hard-deleted,
 * and each action writes an append-only {@code owncast_moderation_audit} row.
 */
@Tag(name = "Owncast Moderation", description = "Owncast moderation surface (/bff/owncast/mod): "
        + "list a brand's streams (with each owner's active-ban flag), hide (force internal), "
        + "kill/ban (owncast_grant banned + hide), restore (lift the ban). MOD|ADMIN|SUPERADMIN; "
        + "authority is the MOD role + domain match, NOT ownership. Domain + moderator identity "
        + "server-derived from the JWT; ban/restore reuse owncast_grant; kill/hide/ban/restore "
        + "ONLY (no grant/govern path).")
@RestController
@RequestMapping("/bff/owncast/mod")
@Validated
public class OwncastModerationController {

    /** OWNCAST_MODERATE — list/hide/kill/restore: MOD or ADMIN or SUPERADMIN. ADMIN and MOD are
     *  documented SIBLINGS (no ADMIN&gt;MOD hierarchy edge), and SUPERADMIN reaches MOD via the
     *  hierarchy; the predicate is EXPLICIT so all three reach the moderation verbs and a plain
     *  USER / a bare OWNCAST streamer is denied. */
    public static final String OWNCAST_MODERATE =
            "hasRole('MOD') or hasRole('ADMIN') or hasRole('SUPERADMIN')";

    private final OwncastModerationService moderation;

    public OwncastModerationController(OwncastModerationService moderation) {
        this.moderation = moderation;
    }

    @Operation(operationId = "listModerationStreams", summary = "List the streams in the MODERATOR's brand (domain server-derived). Each "
            + "row: ownerSubject, title, visibility, and whether the owner currently holds an "
            + "active broadcast BAN (owncast_grant). MOD|ADMIN|SUPERADMIN.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Stream list returned for the moderator's brand"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_MODERATE)
    @GetMapping("/streams")
    public Mono<OwncastModerationDto.StreamList> listStreams(Authentication auth) {
        return moderation.listStreams(auth).collectList().map(OwncastModerationDto.StreamList::new);
    }

    @Operation(operationId = "hideStream", summary = "HIDE a target owner's stream: force visibility=internal in the "
            + "moderator's brand (authority = MOD role + domain match, NOT ownership). 404 if the "
            + "target has no stream in this brand. MOD|ADMIN|SUPERADMIN.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Stream visibility forced to internal; audit row written"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Target owner has no stream in the moderator's brand", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_MODERATE)
    @PostMapping("/streams/{ownerSubject}/hide")
    public Mono<ResponseEntity<OwncastModerationDto.ActionResult>> hide(
            @PathVariable String ownerSubject,
            @Valid @RequestBody(required = false) OwncastModerationDto.ModAction body,
            Authentication auth) {
        return moderation.hide(auth, ownerSubject, reasonOf(body))
                .map(ResponseEntity::ok);
    }

    @Operation(operationId = "banStream", summary = "KILL a target owner's stream: write owncast_grant(banned) active (the "
            + "existing OwncastBroadcastGuard ban>grant then blocks the owner's public broadcast) "
            + "AND force the stream internal. Audit-preserving (never hard-delete). "
            + "MOD|ADMIN|SUPERADMIN.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Stream banned (owncast_grant banned written) and forced internal; audit row written"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Target owner has no stream in the moderator's brand", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_MODERATE)
    @PostMapping("/streams/{ownerSubject}/ban")
    public Mono<ResponseEntity<OwncastModerationDto.ActionResult>> ban(
            @PathVariable String ownerSubject,
            @Valid @RequestBody(required = false) OwncastModerationDto.ModAction body,
            Authentication auth) {
        return moderation.ban(auth, ownerSubject, reasonOf(body))
                .map(ResponseEntity::ok);
    }

    @Operation(operationId = "restoreStream", summary = "RESTORE a target owner: CAS the active broadcast ban active->revoked "
            + "(the row is retained = audit). Does NOT auto-republish — the owner re-chooses "
            + "visibility. MOD|ADMIN|SUPERADMIN.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Broadcast ban revoked (row retained for audit); owner must re-choose visibility"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "No active broadcast ban found for this owner", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(OWNCAST_MODERATE)
    @PostMapping("/streams/{ownerSubject}/restore")
    public Mono<ResponseEntity<OwncastModerationDto.ActionResult>> restore(
            @PathVariable String ownerSubject,
            @Valid @RequestBody(required = false) OwncastModerationDto.ModAction body,
            Authentication auth) {
        return moderation.restore(auth, ownerSubject, reasonOf(body))
                .map(ResponseEntity::ok);
    }

    private static String reasonOf(OwncastModerationDto.ModAction body) {
        return body == null ? null : body.reason();
    }
}
