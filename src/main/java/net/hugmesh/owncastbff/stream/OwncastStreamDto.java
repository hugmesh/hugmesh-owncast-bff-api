package net.hugmesh.owncastbff.stream;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

/**
 * The JSON shapes crossing the {@code /bff/owncast/user/stream} HTTP boundary for a
 * streamer's OWN stream + self-visibility. Plain records
 * ({@code @JsonIgnoreProperties(ignoreUnknown)}). The OWNER ({@code user_subject}) and the
 * {@code domain} are NEVER read from the body — the service derives them from the validated
 * JWT (owner == Casdoor sub; domain == validated issuer), so a caller cannot act as another
 * streamer or forge a cross-tenant scope.
 */
public final class OwncastStreamDto {

    private OwncastStreamDto() {}

    /**
     * An {@code owncast_stream} row as returned to its OWNING streamer.
     *
     * <p>{@code playbackUrl} is the streamer's per-instance Owncast HLS playback endpoint —
     * populated ONLY for a caller PERMITTED to view the stream (the existing broadcast/
     * visibility gate in {@code OwncastStreamService}), and {@code null} otherwise so the media
     * endpoint is never leaked to an unauthorized or cross-tenant caller. It is also
     * {@code null} when no playback URL template is configured (the template is unset by default).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Stream(String id, String domain, String userSubject, String title,
                         String description, String visibility,
                         Instant createdAt, Instant updatedAt, String playbackUrl) {
        public static Stream of(OwncastStream s) {
            return new Stream(s.id(), s.domain(), s.userSubject(), s.title(), s.description(),
                    s.visibility(), s.createdAt(), s.updatedAt(), s.playbackUrl());
        }
    }

    // ── request bodies ─────────────────────────────────────────────────

    /** {@code PUT /bff/owncast/user/stream} — create-or-update the streamer's own title +
     *  description. Both are optional free text (a stream can carry an empty title). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Upsert(
            @Size(max = 256, message = "title is too long")
            String title,
            @Size(max = 2048, message = "description is too long")
            String description) {}

    /** {@code PUT /bff/owncast/user/stream/visibility} — flip the streamer's own stream
     *  visibility. {@code visibility} is {@code public} or {@code internal}; a public flip is
     *  gated server-side on an active broadcast grant (the service rejects neither value here,
     *  only blank — the exact-value check + the grant gate live in the service). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Visibility(
            @NotBlank(message = "visibility is required")
            @Size(max = 16, message = "visibility is invalid")
            String visibility) {}
}
