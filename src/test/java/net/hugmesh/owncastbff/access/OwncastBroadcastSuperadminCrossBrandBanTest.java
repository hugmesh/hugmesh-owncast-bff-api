package net.hugmesh.owncastbff.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.owncastbff.security.PrincipalDomain;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * REGRESSION for the finding "a SUPERADMIN broadcast ban/timeout is stamped to {@code
 * default} but {@link OwncastBroadcastGuard} queries the victim's OWN brand, so the ban
 * returns HTTP 200 yet silently never takes effect" — a FAIL-OPEN ban. The twin of
 * wiki-bff's {@code WikiAccessSuperadminCrossBrandBanTest}; the fix makes a SUPERADMIN
 * ban target the VICTIM's brand (a resolved {@code targetDomain}) instead of letting the
 * actor's {@code null} cross-domain scope be normalised to {@code default} by
 * {@link OwncastGrantRepository#insertActive}.
 *
 * <p>This drives the REAL {@link OwncastBroadcastService} write + the REAL
 * {@link OwncastBroadcastGuard} read + the REAL {@link PrincipalDomain} over an
 * IN-MEMORY fake of {@link OwncastGrantRepository}. The fake stubs ONLY the derived-query
 * and {@code insertActiveRow} abstract methods — the {@code default} methods
 * ({@code insertActive} / {@code findActive} / {@code activeFor}), which carry the
 * {@code DomainScope.isUnscoped(domain) -> DEFAULT_DOMAIN} coalescing that produced the bug
 * (and that every guard read depends on), run FOR REAL. No container is booted (the sibling
 * slice tests need a
 * Testcontainers Postgres; this round-trip does not).
 *
 * <ul>
 *   <li><b>EXPLOIT CLOSED</b> — a SUPERADMIN bans a brand-X streamer with {@code
 *       targetDomain="brandx"}; the row lands in {@code brandx}; the guard's brand-X read
 *       ({@code activeFor(subject,"brandx")}) NOW finds the ban and DENIES (403). Before
 *       the fix the row was {@code default} and the granted streamer kept broadcasting.</li>
 *   <li><b>FAIL-CLOSED</b> — a SUPERADMIN ban with NO/unknown {@code targetDomain} in
 *       multi-brand mode is rejected (400) and NO row is written, rather than silently
 *       stamping a {@code default} ban that no brand's guard would ever match.</li>
 *   <li><b>SINGLE-ISSUER UNCHANGED</b> — the legacy deployment shape still stamps
 *       {@code default} for a SUPERADMIN (no 400), and the guard still matches it.</li>
 *   <li><b>LEGIT scoped-ADMIN unchanged</b> — a brand-X ADMIN's ban still lands in their
 *       issuer-derived brand and {@code targetDomain} is ignored.</li>
 * </ul>
 */
class OwncastBroadcastSuperadminCrossBrandBanTest {

    /** Multi-brand registry: brandx + brandy issuers (isMultiIssuer() == true, so a
     *  SUPERADMIN cross-brand write MUST name a target brand). */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

    /** The LEGACY single-issuer registry: no app.tenancy.issuers => every principal is
     *  "default" and isMultiIssuer() == false. */
    private static final DomainRegistry SINGLE = new DomainRegistry("https://id.solo.example", "");

    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_SOLO = "https://id.solo.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return tag + "-" + SEQ.incrementAndGet(); }

    /** The fake repo's backing store — the rows a write actually landed. */
    private final List<OwncastGrant> store = new CopyOnWriteArrayList<>();

    private OwncastGrantRepository repo;
    private OwncastBroadcastService service;
    private OwncastBroadcastGuard guard;

    @BeforeEach
    void setUp() {
        store.clear();
        repo = inMemoryRepo();
        PrincipalDomain pd = new PrincipalDomain(MULTI);
        service = new OwncastBroadcastService(repo, pd);
        guard = new OwncastBroadcastGuard(repo, pd);
    }

    // ── EXPLOIT CLOSED ────────────────────────────────────────────────────────

    /**
     * THE finding: a SUPERADMIN bans a brand-X streamer who holds an active broadcast
     * grant. With {@code targetDomain="brandx"} the ban row lands in {@code brandx}, so
     * the guard's brand-X read finds it and DENIES — the ban actually bites.
     */
    @Test
    void superadminBan_targetsVictimBrand_brandXBroadcastDenied() {
        String u = user("xbrand-ban");
        Authentication adminX = principal(ISS_X, "admin-x", "admin");
        Authentication victimX = principal(ISS_X, u, "user", "owncast");

        // The victim is a granted brand-X streamer: broadcast is ALLOWED pre-ban.
        service.grant(u, "go live", null, adminX).block();
        StepVerifier.create(guard.assertCanBroadcast(victimX)).verifyComplete();

        // A SUPERADMIN (null actor-scope) bans this brand-X subject, naming the victim brand.
        Authentication superadmin = principal(ISS_X, "root", "superadmin");
        OwncastGrant row = service.ban(u, "abuse", "brandx", superadmin).block();

        // The row is STAMPED with the victim brand (not 'default', which no brand's guard would
        // match).
        assertThat(row.domain())
                .as("a SUPERADMIN cross-brand ban is stamped to the victim brand, not 'default'")
                .isEqualTo("brandx");
        assertThat(repo.activeFor(u, "brandx").collectList().block())
                .as("the brand-X broadcast working set now contains the ban")
                .anySatisfy(a -> assertThat(a.accessType()).isEqualTo(OwncastGrant.TYPE_BANNED));

        // The guard's brand-X read NOW sees the ban and DENIES (ban > grant). Exploit closed.
        StepVerifier.create(guard.assertCanBroadcast(victimX))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
    }

    /** The same for a TIMEOUT (the bounded-window twin of ban — same write path). */
    @Test
    void superadminTimeout_targetsVictimBrand_brandXBroadcastDenied() {
        String u = user("xbrand-timeout");
        Authentication adminX = principal(ISS_X, "admin-x", "admin");
        Authentication victimX = principal(ISS_X, u, "user", "owncast");
        service.grant(u, "go live", null, adminX).block();

        Authentication superadmin = principal(ISS_X, "root", "superadmin");
        OwncastGrant row = service.timeout(u, 3600, "cooldown", "brandx", superadmin).block();

        assertThat(row.domain()).isEqualTo("brandx");
        StepVerifier.create(guard.assertCanBroadcast(victimX))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
    }

    // ── FAIL-CLOSED ───────────────────────────────────────────────────────────

    @Test
    void superadminBan_withoutTargetDomain_failsClosed_noRowWritten() {
        String u = user("xbrand-notgt");
        Authentication superadmin = principal(ISS_X, "root", "superadmin");

        // No targetDomain in multi-brand mode => 400 (rather than a 'default' ban no brand's guard
        // would match).
        StepVerifier.create(service.ban(u, "abuse", null, superadmin))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .verify();

        // Nothing was written in EITHER brand (no silent no-effect ban anywhere).
        assertThat(store).as("a fail-closed ban writes NO row at all").isEmpty();
        assertThat(repo.activeFor(u, "default").collectList().block()).isEmpty();
        assertThat(repo.activeFor(u, "brandx").collectList().block()).isEmpty();
    }

    @Test
    void superadminBan_withUnknownTargetDomain_failsClosed() {
        String u = user("xbrand-bogus");
        Authentication superadmin = principal(ISS_X, "root", "superadmin");

        // An unknown (untrusted) brand cannot be targeted — fail closed rather than stamping
        // a brand no Casdoor backs (mirrors DomainRegistry.isKnownDomain).
        StepVerifier.create(service.ban(u, "abuse", "roguebrand", superadmin))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .verify();
        assertThat(store).isEmpty();
    }

    /** {@code default} is a back-compat sentinel, NOT a real brand: a SUPERADMIN may not
     *  launder a no-effect ban through it by naming it explicitly. */
    @Test
    void superadminBan_targetingDefaultLiterally_failsClosed() {
        String u = user("xbrand-default");
        Authentication superadmin = principal(ISS_X, "root", "superadmin");

        StepVerifier.create(service.ban(u, "abuse", DomainRegistry.DEFAULT_DOMAIN, superadmin))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .verify();
        assertThat(store).isEmpty();
    }

    // ── SINGLE-ISSUER: legacy behaviour MUST be unchanged ─────────────────────

    /**
     * The guardrail on the fix itself: in a single-issuer (legacy) deployment there IS no
     * per-brand victim to name, every principal resolves to {@code default}, and a
     * SUPERADMIN ban must still succeed stamped {@code default} — AND still bite, because
     * the guard reads {@code default} too. The fix must never 400 here.
     */
    @Test
    void singleIssuer_superadminBan_keepsLegacyDefault_andStillBites() {
        PrincipalDomain solo = new PrincipalDomain(SINGLE);
        OwncastBroadcastService svc = new OwncastBroadcastService(repo, solo);
        OwncastBroadcastGuard grd = new OwncastBroadcastGuard(repo, solo);

        String u = user("solo-ban");
        Authentication adminSolo = principal(ISS_SOLO, "admin-solo", "admin");
        Authentication victim = principal(ISS_SOLO, u, "user", "owncast");
        svc.grant(u, "go live", null, adminSolo).block();
        StepVerifier.create(grd.assertCanBroadcast(victim)).verifyComplete();

        // A SUPERADMIN ban with NO targetDomain still succeeds and stamps 'default'.
        Authentication superadmin = principal(ISS_SOLO, "root", "superadmin");
        OwncastGrant row = svc.ban(u, "abuse", null, superadmin).block();
        assertThat(row.domain())
                .as("single-issuer SUPERADMIN write keeps the legacy 'default' brand")
                .isEqualTo(DomainRegistry.DEFAULT_DOMAIN);

        // And it BITES — the single-issuer guard reads 'default' too.
        StepVerifier.create(grd.assertCanBroadcast(victim))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
    }

    // ── LEGIT unchanged: scoped ADMIN bans in own brand; targetDomain ignored ─

    /**
     * A brand-X ADMIN's ban still lands in brandx (issuer-derived), and a
     * {@code targetDomain} pointing at another brand is IGNORED — an ADMIN can never
     * redirect a write cross-brand.
     */
    @Test
    void scopedAdminBan_staysInOwnBrand_targetDomainIgnored() {
        String u = user("xbrand-admin");
        Authentication adminX = principal(ISS_X, "admin-x", "admin");

        // Even with a forged targetDomain="brandy", a scoped ADMIN's ban lands in brandx.
        OwncastGrant row = service.ban(u, "abuse", "brandy", adminX).block();
        assertThat(row.domain())
                .as("a scoped ADMIN's write is issuer-derived (brandx); targetDomain is inert")
                .isEqualTo("brandx");
        assertThat(repo.activeFor(u, "brandy").collectList().block())
                .as("no row leaked into the forged target brand")
                .isEmpty();
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** A JWT-principal Authentication for a brand (issuer) + subject + Casdoor roles. */
    private static Authentication principal(String issuer, String subject, String... roles) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).claim("iss", issuer).issuer(issuer)
                .claim("roles", List.of(roles)).build();
        List<GrantedAuthority> auths = new ArrayList<>();
        auths.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) auths.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()));
        return new UsernamePasswordAuthenticationToken(jwt, "n/a", auths);
    }

    /**
     * An in-memory {@link OwncastGrantRepository}: the ABSTRACT derived queries +
     * {@code insertActiveRow} are stubbed against {@link #store}, while the {@code default}
     * methods run FOR REAL — so the real {@code insertActive} domain-coalescing and the real
     * scoped/unscoped {@code findActive}/{@code activeFor} dispatch are under test.
     */
    private OwncastGrantRepository inMemoryRepo() {
        OwncastGrantRepository r = mock(OwncastGrantRepository.class);

        // Run the REAL default methods (the code under test).
        doCallRealMethod().when(r).insertActive(any(), any(), any(), any(), any(), any());
        doCallRealMethod().when(r).findActive(any(), any(), any());
        doCallRealMethod().when(r).activeFor(any(), any());

        // INSERT: record the row exactly as the real insertActive resolved the brand.
        when(r.insertActiveRow(any(), any(), any(), any(), any(), any())).thenAnswer(inv -> {
            String id = "id-" + SEQ.incrementAndGet();
            store.add(new OwncastGrant(id, inv.getArgument(0), inv.getArgument(1),
                    inv.getArgument(2), OwncastGrant.STATE_ACTIVE, inv.getArgument(3),
                    inv.getArgument(4), Instant.now(), inv.getArgument(5), null));
            return Mono.just(id);
        });

        // findActive — scoped (AND domain = ?) and unscoped (SUPERADMIN bypass).
        when(r.findFirstByUserSubjectAndAccessTypeAndStateAndDomainOrderByCreatedAtDescIdAsc(
                any(), any(), any(), any())).thenAnswer(inv -> Mono.justOrEmpty(first(row ->
                        row.userSubject().equals(inv.getArgument(0))
                                && row.accessType().equals(inv.getArgument(1))
                                && row.state().equals(inv.getArgument(2))
                                && row.domain().equals(inv.getArgument(3)))));
        when(r.findFirstByUserSubjectAndAccessTypeAndStateOrderByCreatedAtDescIdAsc(
                any(), any(), any())).thenAnswer(inv -> Mono.justOrEmpty(first(row ->
                        row.userSubject().equals(inv.getArgument(0))
                                && row.accessType().equals(inv.getArgument(1))
                                && row.state().equals(inv.getArgument(2)))));

        // activeFor — the guard's working-set read, scoped and unscoped.
        when(r.findByUserSubjectAndStateAndDomainOrderByAccessTypeAscCreatedAtDesc(
                any(), any(), any())).thenAnswer(inv -> Flux.fromIterable(all(row ->
                        row.userSubject().equals(inv.getArgument(0))
                                && row.state().equals(inv.getArgument(1))
                                && row.domain().equals(inv.getArgument(2)))));
        when(r.findByUserSubjectAndStateOrderByAccessTypeAscCreatedAtDesc(
                any(), any())).thenAnswer(inv -> Flux.fromIterable(all(row ->
                        row.userSubject().equals(inv.getArgument(0))
                                && row.state().equals(inv.getArgument(1)))));
        return r;
    }

    private Optional<OwncastGrant> first(java.util.function.Predicate<OwncastGrant> p) {
        return store.stream().filter(p).findFirst();
    }

    private List<OwncastGrant> all(java.util.function.Predicate<OwncastGrant> p) {
        return store.stream().filter(p).toList();
    }
}
