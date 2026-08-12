package net.hugmesh.owncastbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Owncast BFF — the broadcast GOVERNANCE plane of the Owncast live-streaming optional
 * service (x86 + GPU-dependent, ships DEFAULT-OFF). It owns the {@code owncast_grant}
 * desired-state overlay (PR2) — the per-principal may-broadcast grant/timeout/ban
 * records that gate whether a (domain-controlled) user's stream may be broadcast — and
 * (PR3) the {@code owncast_stream} self-visibility table + own-visibility flip, shipped.
 * The per-streamer provisioning effector that would feed a streamer-ApplicationSet is
 * still 🔭 planned (not yet on {@code main} — see the README Roadmap), independent of
 * PR3.
 *
 * <p>Owncast is single-broadcaster per instance, so the platform runs one Owncast
 * Deployment + PVC + Service <b>per APPROVED streamer</b>, provisioned on-grant,
 * default-deny. This BFF is NOT the media plane:
 *
 * <pre>browser -> fe-gateway /bff/owncast/** -> THIS BFF -> owncast_grant Postgres overlay
 * OBS     -> Headscale (tailnet) -> per-streamer Owncast :1935 (RTMP ingest, off public)
 * browser -> fe-gateway /owncast/** (HLS) -> per-streamer Owncast :8080 (playback)</pre>
 *
 * <p>This BFF wraps the governance store per ROLE + ACTION (defence in depth on top of
 * the gateway route-access ROLE_OWNCAST floor):
 *
 * <ul>
 *   <li>BROADCAST — DEFAULT-DENY, GRANT-ONLY: a principal may broadcast iff an active
 *       non-expired {@code owncast_grant} broadcast grant exists AND no active ban; there
 *       is NO static role that confers it. Enforced programmatically by
 *       {@code OwncastBroadcastGuard} (a static SpEL cannot consult the DB).</li>
 *   <li>GOVERN (grant/timeout/ban/restore) — {@code OWNCAST_GOVERN = hasRole('ADMIN') or
 *       hasRole('SUPERADMIN')} — an ADMIN decides which of their domain's users may
 *       broadcast;</li>
 *   <li>MANAGE — {@code OWNCAST_MANAGE = hasRole('SUPERADMIN')} — list-all + history
 *       here; the per-domain service-enable + GPU-node-affinity check and the
 *       provisioning effector are still 🔭 planned generator-devops work (see the
 *       README Roadmap), not yet on a scheduled PR.</li>
 * </ul>
 *
 * <p>Every surface is DOMAIN-SCOPED (multi-brand): the {@code domain} is derived
 * SERVER-SIDE from the validated token issuer, so a scoped ADMIN of brand X governs
 * ONLY brand X's streamers; SUPERADMIN is the cross-domain bypass (and is exempt from a
 * ban). The granting admin is tracked from the JWT subject ({@code granted_by_subject});
 * a caller can never act under another admin. The self-visibility {@code owncast_stream}
 * table (PR3) and the moderation surface (PR4) are both shipped; the
 * streamer-ApplicationSet reconciler and the {@code sd-owncast-player} card kind remain
 * 🔭 planned (see the README Roadmap) — this app class covers the BFF skeleton, the
 * grant overlay, the self-visibility surface and the moderation surface, all merged to
 * {@code main}.
 */
@SpringBootApplication
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
public class OwncastBffApplication {
    public static void main(String[] args) {
        SpringApplication.run(OwncastBffApplication.class, args);
    }
}
