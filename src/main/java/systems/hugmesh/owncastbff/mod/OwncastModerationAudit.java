package systems.hugmesh.owncastbff.mod;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code owncast_moderation_audit} row — the APPEND-ONLY local journal entry of one
 * moderator action on the moderation surface (schema in Liquibase
 * {@code db/changelog/006-owncast-moderation-audit.xml}).
 *
 * <p>The actual ban/restore STATE lives in {@code owncast_grant} (active->revoked,
 * audit-preserving) and the hide STATE in {@code owncast_stream}; this row is the
 * moderator-action JOURNAL layered on top, so a moderator's kill/hide/restore is traceable
 * locally even for a hide (which mutates no {@code owncast_grant} row). It is NOT a parallel
 * ban mechanism.
 *
 * <ul>
 *   <li>{@code domain} — the MODERATOR's brand, derived SERVER-SIDE from the validated issuer
 *       (NEVER a request field). A row records an action WITHIN one brand only.</li>
 *   <li>{@code actorSubject} — the acting moderator's Casdoor subject.</li>
 *   <li>{@code targetSubject} — the owner/streamer the action was taken against.</li>
 *   <li>{@code action} — {@link #ACTION_KILL} / {@link #ACTION_HIDE} / {@link #ACTION_RESTORE}
 *       (CHECK-constrained in the DB).</li>
 *   <li>{@code reason} — optional free text (audited).</li>
 * </ul>
 */
@Table("owncast_moderation_audit")
public record OwncastModerationAudit(
        @Id
        @Column("id")
        String id,
        @Column("domain")
        String domain,
        @Column("actor_subject")
        String actorSubject,
        @Column("target_subject")
        String targetSubject,
        @Column("action")
        String action,
        @Column("reason")
        String reason,
        @Column("created_at")
        Instant createdAt) {

    /** A KILL: write an {@code owncast_grant(banned)} active row AND force the stream internal. */
    public static final String ACTION_KILL = "kill";
    /** A HIDE: force the owner's stream {@code visibility=internal} (no grant row change). */
    public static final String ACTION_HIDE = "hide";
    /** A RESTORE: CAS the active ban active->revoked (the owner re-chooses visibility). */
    public static final String ACTION_RESTORE = "restore";
}
