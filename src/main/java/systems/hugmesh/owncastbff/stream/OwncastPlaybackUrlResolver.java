package systems.hugmesh.owncastbff.stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Resolves a streamer's per-instance Owncast HLS PLAYBACK endpoint from the per-streamer
 * media-plane address template. The media plane is SEPARATE from this governance BFF: the
 * platform runs one Owncast Deployment per APPROVED streamer (HLS {@code :8080} behind the
 * gateway — see the README architecture). This resolver turns the owning streamer's identity
 * (subject + brand) into the URL their viewer/player uses, WITHOUT this BFF holding a stream
 * key or talking to the media plane.
 *
 * <p><b>DARK BY DEFAULT (the additive-safety flag).</b> The template
 * ({@code owncast.playback.url-template}) is UNSET by default, so {@link #resolve} returns
 * {@code null} and the {@code playbackUrl} field is simply absent from responses until an
 * operator opts in by configuring the template. Nothing about existing behaviour changes when
 * the template is unset. The template substitutes two placeholders:
 * <ul>
 *   <li>{@code {domain}} — the brand/tenant the stream belongs to (server-derived, never a
 *       request field);</li>
 *   <li>{@code {subject}} — the OWNING streamer's Casdoor subject.</li>
 * </ul>
 * e.g. {@code https://{domain}.example/owncast/{subject}/hls/stream.m3u8}.
 *
 * <p>This resolver only FORMATS the URL — it does NO authorization. The decision of WHETHER a
 * caller may see the URL at all is made by the existing broadcast/visibility gate in
 * {@code OwncastStreamService} (the URL is populated ONLY for a caller permitted to view the
 * stream); an unauthorized or cross-tenant caller never reaches this resolver for that stream.
 */
@Component
public class OwncastPlaybackUrlResolver {

    private final String template;

    public OwncastPlaybackUrlResolver(
            @Value("${owncast.playback.url-template:}") String template) {
        this.template = template == null ? "" : template.trim();
    }

    /**
     * The HLS playback URL for the stream owned by {@code subject} in {@code domain}, or
     * {@code null} when no template is configured (dark by default) or when either input is
     * blank. Pure string formatting — never throws, never contacts the media plane.
     */
    public String resolve(String domain, String subject) {
        if (template.isEmpty() || domain == null || domain.isBlank()
                || subject == null || subject.isBlank()) {
            return null;
        }
        return template
                .replace("{domain}", domain)
                .replace("{subject}", subject);
    }
}
