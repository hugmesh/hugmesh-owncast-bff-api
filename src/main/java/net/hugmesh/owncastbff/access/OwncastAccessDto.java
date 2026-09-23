package net.hugmesh.owncastbff.access;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/owncast/.../access} HTTP boundary for the
 * broadcast grant/timeout/ban overlay. Plain records
 * ({@code @JsonIgnoreProperties(ignoreUnknown)}). The acting principal's
 * {@code grantedBy} + {@code domain} are NEVER read from the body — the service stamps
 * them from the validated JWT (granted_by == Casdoor sub; domain == validated issuer) so
 * a caller cannot act under another admin or forge a cross-tenant scope.
 */
public final class OwncastAccessDto {

    private OwncastAccessDto() {}

    /** An {@code owncast_grant} row as returned to a manage/audit reader. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Access(String id, String domain, String userSubject, String accessType,
                         String state, String grantedBySubject, String reason,
                         Instant createdAt, Instant expiresAt, Instant revokedAt) {
        public static Access of(OwncastGrant a) {
            return new Access(a.id(), a.domain(), a.userSubject(), a.accessType(), a.state(),
                    a.grantedBySubject(), a.reason(), a.createdAt(), a.expiresAt(), a.revokedAt());
        }
    }

    /** The list-response wrapper. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AccessList(List<Access> access) {}

    // ── request bodies ─────────────────────────────────────────────────

    /**
     * {@code POST .../access/grant} and {@code .../access/ban} — a permanent override.
     * {@code reason} is optional free text (audited). {@code targetDomain} is the VICTIM's
     * brand, consulted ONLY for a SUPERADMIN cross-brand write (a scoped ADMIN's brand is
     * always issuer-derived and this field is ignored): a SUPERADMIN bans a brand-X streamer
     * by passing {@code targetDomain="brandx"} so the row lands in (and the broadcast guard
     * matches) the victim's brand instead of the {@code default} domain, where no brand's
     * broadcast guard would ever match it.
     *
     * @param userSubject  Casdoor subject of the principal to grant or ban; required,
     *                     max 400 characters
     * @param reason       optional free-text audit reason for the action; max 1 024 characters
     * @param targetDomain the VICTIM's brand for a SUPERADMIN cross-brand write; ignored
     *                     for a scoped ADMIN (issuer-derived); max 64 characters
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GrantOrBan(
            @NotBlank(message = "userSubject is required")
            @Size(max = 400, message = "userSubject is too long")
            String userSubject,
            @Size(max = 1024, message = "reason is too long")
            String reason,
            @Size(max = 64, message = "targetDomain is too long")
            String targetDomain) {}

    /**
     * {@code POST .../access/timeout} — a {@code banned} override with a FUTURE expiry.
     * {@code ttlSeconds} drives the auto-restore instant; it must be positive.
     * {@code targetDomain} is the VICTIM's brand for a SUPERADMIN cross-brand timeout (same
     * contract as {@link GrantOrBan#targetDomain()}; ignored for a scoped ADMIN).
     *
     * @param userSubject  Casdoor subject of the principal to timeout; required,
     *                     max 400 characters
     * @param ttlSeconds   duration in seconds until the timeout auto-restores; must be positive
     * @param reason       optional free-text audit reason for the action; max 1 024 characters
     * @param targetDomain the VICTIM's brand for a SUPERADMIN cross-brand timeout; ignored
     *                     for a scoped ADMIN (issuer-derived); max 64 characters
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Timeout(
            @NotBlank(message = "userSubject is required")
            @Size(max = 400, message = "userSubject is too long")
            String userSubject,
            @Positive(message = "ttlSeconds must be positive")
            long ttlSeconds,
            @Size(max = 1024, message = "reason is too long")
            String reason,
            @Size(max = 64, message = "targetDomain is too long")
            String targetDomain) {}
}
