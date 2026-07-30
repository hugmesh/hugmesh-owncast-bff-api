package systems.hugmesh.owncastbff.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import systems.hugmesh.owncastbff.access.OwncastAccessDto;
import systems.hugmesh.owncastbff.access.OwncastGrant;

/**
 * GraalVM native-image / AOT reachability hints for the bits the static analyzer
 * cannot see through on its own — mirrors hugmesh-wiki-bff-api / forum-bff /
 * user-bff / federation-api {@code NativeHintsConfig}.
 *
 * <p>Spring Boot's own AOT processing covers the framework surface (the WebFlux
 * codecs, the reactive OAuth2 resource-server JWT pipeline, R2DBC, and the Jackson
 * auto-configuration). What it cannot always infer:
 *
 * <ul>
 *   <li><b>JSON-bound DTOs / entities</b> reached reflectively through Jackson — the
 *       records crossing the HTTP boundary ({@link OwncastAccessDto} nested records) and
 *       the persistence entity ({@link OwncastGrant}). They need explicit binding hints
 *       so their canonical constructors/accessors survive native image.</li>
 *   <li><b>The springdoc Swagger UI webjar resources</b> — native-image strips
 *       classpath resources by default; the bundled assets 404 without an explicit
 *       resource-include pattern. The raw {@code /v3/api-docs} JSON (what
 *       ng-openapi-gen + the docs pipeline consume) is bean-produced and unaffected.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(NativeHintsConfig.Hints.class)
public class NativeHintsConfig {

    static class Hints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection()
                    .registerType(OwncastAccessDto.Access.class, dtoCategories())
                    .registerType(OwncastAccessDto.AccessList.class, dtoCategories())
                    .registerType(OwncastAccessDto.GrantOrBan.class, dtoCategories())
                    .registerType(OwncastAccessDto.Timeout.class, dtoCategories())
                    .registerType(OwncastGrant.class, dtoCategories());

            hints.resources()
                    .registerPattern("META-INF/resources/webjars/swagger-ui/*")
                    .registerPattern("META-INF/resources/webjars/swagger-ui/**");
        }

        private static MemberCategory[] dtoCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
                    MemberCategory.DECLARED_FIELDS,
            };
        }
    }
}
