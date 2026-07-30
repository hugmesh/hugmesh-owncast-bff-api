package systems.hugmesh.owncastbff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;

/**
 * Context-load smoke test: the full Spring context boots under the {@code test}
 * profile. The shared {@link PostgresTestSupport} base auto-wires R2DBC + Liquibase to
 * a fresh per-class Testcontainers Postgres database (the real production Postgres
 * driver + the real Liquibase changelog), so the repositories + r2dbc-converters wire
 * over a real schema — the Boot-4 dual-connection-safe replacement for the old in-mem
 * H2 dual-connection. The reactive JWT decoder is mocked so no live Casdoor issuer is
 * contacted. This proves the controller, service, repository, the broadcast guard, and
 * the security + native-hints config wire together.
 */
@SpringBootTest
@ActiveProfiles("test")
class OwncastBffApplicationContextTest extends PostgresTestSupport {

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the
     *  oauth2 resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void contextLoads() {
        // success = the application context started with every bean wired.
    }
}
