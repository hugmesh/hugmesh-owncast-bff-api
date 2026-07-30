package systems.hugmesh.owncastbff.stream;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code owncast_stream} row — the OWNER-controlled SELF-VISIBILITY descriptor of
 * a streamer's own stream (schema in Liquibase {@code db/changelog/005-owncast-stream.xml}).
 * It is the sibling of the ADMIN-controlled {@code owncast_grant} broadcast-governance
 * overlay: where the overlay says WHETHER a user may broadcast (default-deny, admin-granted),
 * this row is the streamer's OWN stream metadata + the visibility flag THEY flip.
 *
 * <ul>
 *   <li>{@code userSubject} — the OWNING streamer's Casdoor subject (== {@code jwt.sub}).
 *       UNIQUE per {@code domain}: at most one stream per streamer per brand.</li>
 *   <li>{@code title} / {@code description} — the streamer's own free-text stream metadata.</li>
 *   <li>{@code visibility} — {@link #VISIBILITY_INTERNAL} (visible only inside the brand,
 *       the default — fail-closed) or {@link #VISIBILITY_PUBLIC} (federated / vanity-cut
 *       visible). The streamer flips this themselves; a flip to PUBLIC is GATED server-side
 *       on the owner holding an active broadcast grant (see {@code OwncastStreamService}).</li>
 *   <li>{@code domain} — the brand/tenant the stream belongs to, derived SERVER-SIDE from
 *       the validated issuer (NEVER a request field). A stream in brand X is invisible to
 *       brand Y.</li>
 *   <li>{@code playbackUrl} — the streamer's per-instance Owncast HLS playback endpoint. This
 *       is a {@link Transient DERIVED, NON-PERSISTED} field (NOT an {@code owncast_stream}
 *       column): it is computed by {@code OwncastPlaybackUrlResolver} and populated ONLY for a
 *       caller PERMITTED to view the stream (the same broadcast/visibility gate). It is
 *       {@code null} for the persisted row and for any caller not permitted to view — so the
 *       media endpoint is never leaked to an unauthorized or cross-tenant caller.</li>
 * </ul>
 */
@Table("owncast_stream")
public record OwncastStream(
        @Id
        @Column("id")
        String id,
        @Column("domain")
        String domain,
        @Column("user_subject")
        String userSubject,
        @Column("title")
        String title,
        @Column("description")
        String description,
        @Column("visibility")
        String visibility,
        @Column("created_at")
        Instant createdAt,
        @Column("updated_at")
        Instant updatedAt,
        @Transient
        String playbackUrl) {

    /**
     * Persistence/canonical 8-arg constructor — the form mapped to the {@code owncast_stream}
     * columns (no {@code playback_url} column exists). Marked {@link PersistenceCreator} so
     * Spring Data R2DBC materialises a row through it, leaving the DERIVED {@code playbackUrl}
     * {@code null}; the service fills {@code playbackUrl} afterwards only for a permitted caller
     * via {@link #withPlaybackUrl(String)}. Keeps every existing 8-arg call site compiling.
     */
    @PersistenceCreator
    public OwncastStream(String id, String domain, String userSubject, String title,
                         String description, String visibility, Instant createdAt, Instant updatedAt) {
        this(id, domain, userSubject, title, description, visibility, createdAt, updatedAt, null);
    }

    /** A copy of this row carrying the given derived {@code playbackUrl} (all persisted fields
     *  unchanged). The service calls this ONLY after the view gate passes. */
    public OwncastStream withPlaybackUrl(String playbackUrl) {
        return new OwncastStream(id, domain, userSubject, title, description, visibility,
                createdAt, updatedAt, playbackUrl);
    }

    /** Visible only WITHIN the brand — the DEFAULT (a new stream is brand-internal until the
     *  streamer makes it public, and a public flip requires an active broadcast grant). */
    public static final String VISIBILITY_INTERNAL = "internal";
    /** PUBLIC / federated — flips the federation module visibility + vanity cut on. Only an
     *  owner who currently holds an active broadcast grant may set/keep this (enforced in
     *  {@code OwncastStreamService}). */
    public static final String VISIBILITY_PUBLIC = "public";

    public boolean isPublic() {
        return VISIBILITY_PUBLIC.equals(visibility);
    }

    /** Normalise an inbound visibility token to one of the two canonical values, or
     *  {@code null} if it is neither (the caller rejects a {@code null} as a bad request). */
    public static String normalizeVisibility(String raw) {
        if (raw == null) return null;
        String v = raw.trim().toLowerCase();
        if (VISIBILITY_PUBLIC.equals(v)) return VISIBILITY_PUBLIC;
        if (VISIBILITY_INTERNAL.equals(v)) return VISIBILITY_INTERNAL;
        return null;
    }
}
