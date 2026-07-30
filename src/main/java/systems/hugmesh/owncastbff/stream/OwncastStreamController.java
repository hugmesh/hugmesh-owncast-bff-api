package systems.hugmesh.owncastbff.stream;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;

/**
 * The streamer's OWN stream + self-visibility surface — {@code /bff/owncast/user/stream}. A
 * streamer controls THEIR OWN stream: get it, set its title/description, and flip its
 * visibility between {@code internal} and {@code public}. The OWNER and the brand are
 * derived SERVER-SIDE from the validated JWT (owner == Casdoor sub; domain == validated
 * issuer) by {@link OwncastStreamService} — never a request field — so a caller can only
 * ever read/modify their own stream in their own brand.
 *
 * <p><b>ROLE MODEL.</b> Mounted under {@code /bff/owncast/user/**}, which the SecurityConfig
 * path gate restricts to {@code ROLE_OWNCAST} (the base service role) — the floor that lets a
 * domain user reach the owncast user surface at all. The SECURITY-CRITICAL extra rule — a
 * stream may only be made/kept PUBLIC by an owner who currently holds an active BROADCAST
 * grant — is enforced in the service (it calls {@code OwncastBroadcastGuard.assertCanBroadcast}
 * on a public flip), NOT by a static path/role gate, because broadcast is default-deny +
 * grant-only and a static SpEL cannot consult the DB.
 */
@Tag(name = "Owncast Stream (self)", description = "A streamer's OWN stream + self-visibility "
        + "(owncast_stream): get/upsert title+description, flip visibility internal<->public. "
        + "Owner + brand server-derived from the JWT. A PUBLIC flip is gated server-side on an "
        + "active broadcast grant (OwncastBroadcastGuard); ROLE_OWNCAST floor.")
@RestController
@RequestMapping("/bff/owncast/user/stream")
@Validated
public class OwncastStreamController {

    private final OwncastStreamService streams;

    public OwncastStreamController(OwncastStreamService streams) {
        this.streams = streams;
    }

    @Operation(operationId = "getMyStream", summary = "Get the CALLING streamer's OWN stream (owner == JWT subject, brand "
            + "server-derived). 404 if the streamer has no stream yet.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Own stream returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_OWNCAST", content = @Content),
            @ApiResponse(responseCode = "404", description = "Streamer has no stream yet", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @GetMapping
    public Mono<ResponseEntity<OwncastStreamDto.Stream>> getMyStream(Authentication auth) {
        return streams.getMyStream(auth)
                .map(s -> ResponseEntity.ok(OwncastStreamDto.Stream.of(s)))
                .switchIfEmpty(Mono.error(ApiException.notFound("no stream for this streamer")));
    }

    @Operation(operationId = "upsertMyStream", summary = "Create-or-update the CALLING streamer's OWN stream title + "
            + "description. A first upsert creates the stream visibility=internal (fail-closed); "
            + "visibility is changed only via the visibility endpoint. Owner + brand server-derived.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Stream created or updated; visibility unchanged"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_OWNCAST", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PutMapping
    public Mono<ResponseEntity<OwncastStreamDto.Stream>> upsertMyStream(
            @Valid @RequestBody OwncastStreamDto.Upsert body, Authentication auth) {
        return streams.upsertMyStream(auth, body.title(), body.description())
                .map(s -> ResponseEntity.ok(OwncastStreamDto.Stream.of(s)));
    }

    @Operation(operationId = "setMyStreamVisibility", summary = "Flip the CALLING streamer's OWN stream visibility to 'public' or "
            + "'internal'. A flip to PUBLIC is ALLOWED ONLY when the owner currently holds an "
            + "active broadcast grant (403 otherwise; SUPERADMIN exempt); a flip to INTERNAL is "
            + "always allowed. 404 if the streamer has no stream yet. Owner + brand server-derived.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Visibility updated"),
            @ApiResponse(responseCode = "400", description = "Validation failed — invalid visibility value", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Public flip denied — no active broadcast grant (OwncastBroadcastGuard)", content = @Content),
            @ApiResponse(responseCode = "404", description = "Streamer has no stream yet", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PutMapping("/visibility")
    public Mono<ResponseEntity<OwncastStreamDto.Stream>> setVisibility(
            @Valid @RequestBody OwncastStreamDto.Visibility body, Authentication auth) {
        return streams.setVisibility(auth, body.visibility())
                .map(s -> ResponseEntity.ok(OwncastStreamDto.Stream.of(s)));
    }
}
