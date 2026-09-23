package net.hugmesh.owncastbff.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * Registers the shared {@code net.hugmesh.commons} security/tenancy beans
 * ({@link DomainRegistry} and {@link TenancyResourceServerConfig}) into
 * this consumer's application context. {@code @Import} is used instead of
 * widening component scan to avoid auto-adopting future commons {@code @Component}
 * classes implicitly. The {@code @ConditionalOnExpression} guard is preserved so
 * single-issuer clusters stay on their existing path.
 */
@Configuration
@Import({DomainRegistry.class, TenancyResourceServerConfig.class})
public class CommonsSecurityConfig {
}
