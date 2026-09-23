package net.hugmesh.owncastbff.access;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code owncast_grant} row — the desired-state record of a per-principal
 * may-broadcast override (schema in Liquibase {@code db/changelog/004-owncast-grant.xml}).
 *
 * <p>The overlay is the source of truth for the broadcast grant / timeout / ban model.
 * Unlike wiki read (which has a static role floor), broadcast is DEFAULT-DENY and
 * GRANT-ONLY — a {@link #TYPE_BROADCAST} grant is the ONLY thing that confers it:
 * <ul>
 *   <li>{@code accessType} — {@link #TYPE_BROADCAST} (a GRANT letting a USER broadcast,
 *       which no role confers) or {@link #TYPE_BANNED} (a BAN/TIMEOUT denying broadcast);
 *       CHECK-constrained in the DB.</li>
 *   <li>{@code state} — {@link #STATE_ACTIVE} while the override is in force; the
 *       service CASes it to {@link #STATE_REVOKED} on restore/revoke (the row is NEVER
 *       deleted — it is the audit trail).</li>
 *   <li>{@code expiresAt} — {@code null} means PERMANENT (a permanent grant, or a
 *       permanent ban); a FUTURE instant means a TIMEOUT that auto-restores when the
 *       clock passes WITHOUT a write ({@link #isEffectiveAt} treats {@code expiresAt <=
 *       now} as no-longer-active).</li>
 *   <li>{@code domain} — the brand/tenant the override belongs to, stamped SERVER-SIDE
 *       from the validated issuer. A scoped ADMIN acts only within their own brand;
 *       SUPERADMIN acts cross-domain.</li>
 * </ul>
 */
@Table("owncast_grant")
public record OwncastGrant(
        @Id
        @Column("id")
        String id,
        @Column("domain")
        String domain,
        @Column("user_subject")
        String userSubject,
        @Column("access_type")
        String accessType,
        @Column("state")
        String state,
        @Column("granted_by_subject")
        String grantedBySubject,
        @Column("reason")
        String reason,
        @Column("created_at")
        Instant createdAt,
        @Column("expires_at")
        Instant expiresAt,
        @Column("revoked_at")
        Instant revokedAt) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    /** A GRANT of may-broadcast to a principal who would not have it by role (broadcast
     *  is default-deny + grant-only — there is no role floor). */
    public static final String TYPE_BROADCAST = "broadcast";
    /** A BAN (or, with a future {@code expiresAt}, a TIMEOUT) denying broadcast. */
    public static final String TYPE_BANNED = "banned";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /** A timed (non-permanent) override whose TTL has passed at {@code now} — an expired
     *  timeout. */
    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    /**
     * Is this override IN EFFECT at {@code now} — i.e. {@code state='active'} AND not
     * past its TTL. An active permanent row ({@code expiresAt} null) is always in effect;
     * an active timed row is in effect only until its {@code expiresAt}. This is the
     * single predicate the request-time enforcement guard applies, so an expired timeout
     * auto-restores (stops denying) WITHOUT a write.
     */
    public boolean isEffectiveAt(Instant now) {
        return isActive() && !isExpiredAt(now);
    }
}
