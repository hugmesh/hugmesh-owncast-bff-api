package net.hugmesh.owncastbff.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * Registers the shared {@code net.hugmesh.commons} security/tenancy beans into
 * this consumer's application context.
 *
 * <p><b>Why this class must exist.</b> {@link DomainRegistry} and
 * {@link TenancyResourceServerConfig} live under {@code net.hugmesh.commons.*}, which the
 * {@code @SpringBootApplication} component scan over {@code net.hugmesh.owncastbff} does NOT
 * cover; without this {@code @Import}, {@code SecurityConfig}'s {@code DomainRegistry}
 * dependency is unsatisfied and every {@code @SpringBootTest} fails to load its context.
 * {@code @Import} is used instead of widening {@code scanBasePackages} to the commons tree so
 * future commons {@code @Component}s are not adopted implicitly.
 * <ul>
 *   <li>{@link DomainRegistry} — the issuer-&gt;domain registry consumed by
 *       {@code SecurityConfig}, the {@code PrincipalDomain} bean and the converter. Its
 *       {@code @Value} constructor wiring
 *       ({@code spring.security.oauth2.resourceserver.jwt.issuer-uri} +
 *       {@code app.tenancy.issuers}) is honoured by {@code @Import} exactly as a component
 *       scan would.</li>
 *   <li>{@link TenancyResourceServerConfig} — the config-gated multi-issuer wiring. Importing
 *       the {@code @Configuration} class preserves its
 *       {@code @ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")} guard, so
 *       the {@code tenantAuthManagerResolver} {@code @Bean} is contributed ONLY when real
 *       {@code issuer=domain} pairs are configured and single-issuer clusters stay on the
 *       existing single-issuer path.</li>
 * </ul>
 *
 * <p>Every consumer of hugmesh-commons drops in this same {@code @Import} configuration,
 * adjusting only its package.
 */
@Configuration
@Import({DomainRegistry.class, TenancyResourceServerConfig.class})
public class CommonsSecurityConfig {
}
