package net.hugmesh.owncastbff.mod;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Size;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/owncast/mod/**} HTTP boundary for the MODERATION
 * surface. Plain records ({@code @JsonIgnoreProperties(ignoreUnknown)}). The moderator's
 * {@code domain} and {@code subject} are NEVER read from the body — the service derives them
 * from the validated JWT (domain == validated issuer; actor == Casdoor sub), so a moderator
 * cannot forge a cross-tenant scope or act under another moderator. The TARGET owner is a
 * path variable (the subject being moderated), never the moderator's own identity.
 */
public final class OwncastModerationDto {

    private OwncastModerationDto() {}

    /**
     * One row of the moderator's stream-list view: the owner + their stream metadata + whether
     * the owner currently holds an active broadcast BAN (joined/looked-up from
     * {@code owncast_grant}). Domain is the moderator's brand (server-derived).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record StreamRow(String ownerSubject, String domain, String title, String visibility,
                            boolean banned) {}

    /** The stream-list response wrapper. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record StreamList(List<StreamRow> streams) {

        /** Defensive, unmodifiable copy on the way in; null stays null (never turned into an NPE). */
        public StreamList {
            streams = streams == null ? null : Collections.unmodifiableList(new ArrayList<>(streams));
        }

        /** Unmodifiable view; the record never hands out its backing list. */
        @Override
        public List<StreamRow> streams() {
            return streams == null ? null : Collections.unmodifiableList(streams);
        }
    }

    /** {@code POST .../streams/{ownerSubject}/(hide|ban|restore)} — an optional moderator
     *  reason (audited). The body carries NO subject/domain — the target is the path variable,
     *  the moderator identity + brand are server-derived. The body is optional. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ModAction(
            @Size(max = 1024, message = "reason is too long")
            String reason) {}

    /** The action-result wrapper returned by hide/ban/restore. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ActionResult(String action, String ownerSubject, String domain, String visibility,
                               boolean banned) {}
}
