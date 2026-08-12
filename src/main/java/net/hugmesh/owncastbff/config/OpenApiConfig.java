package net.hugmesh.owncastbff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Minimal OpenAPI document metadata for the owncast BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed client for the paired hugmesh-owncast-ui (PR5) and the docs
 * pipeline key off these fields. A programmatic {@link OpenAPI} bean is used
 * (rather than the {@code @OpenAPIDefinition} annotation) so the metadata is plain
 * bean wiring — no annotation reflection scan, which keeps the GraalVM native
 * build hint surface minimal.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI owncastBffOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("hugmesh-owncast-bff-api")
                        .version("0.2.0")
                        .description("Owncast BFF API (/bff/owncast/**) — the broadcast governance plane "
                                + "for the Owncast live-streaming optional service. Owns the owncast_grant "
                                + "grant/timeout/ban overlay (cloned from wiki_access): DEFAULT-DENY broadcast "
                                + "enforced at request time by OwncastBroadcastGuard (an active broadcast grant "
                                + "AND NOT an active ban, precedence ban>grant, SUPERADMIN exempt); the "
                                + "owncast_stream owner-controlled self-visibility surface (/bff/owncast/user/"
                                + "stream) with a gated playbackUrl; and the /bff/owncast/mod moderation surface "
                                + "(list/hide/kill/restore) with its own owncast_moderation_audit journal. "
                                + "Grant/timeout/ban/restore gated OWNCAST_GOVERN (admin|superadmin); list-all/"
                                + "history gated OWNCAST_MANAGE (superadmin); moderation gated MOD|admin|"
                                + "superadmin. All surfaces are domain-scoped per multi-brand: a scoped ADMIN "
                                + "governs only own-brand streamers. The per-streamer Owncast media instances "
                                + "(RTMP/HLS) are SEPARATE Deployments, not this BFF."));
    }
}
