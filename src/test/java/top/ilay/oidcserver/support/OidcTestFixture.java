package top.ilay.oidcserver.support;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.Role;
import run.halo.app.core.extension.User;
import run.halo.app.core.user.service.RoleService;
import run.halo.app.infra.ExternalUrlSupplier;
import run.halo.app.plugin.ReactiveSettingFetcher;
import top.ilay.oidcserver.config.OidcSettings;
import top.ilay.oidcserver.dto.OidcClientRequest;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.protocol.OidcValidation;
import top.ilay.oidcserver.service.OidcClientService;
import top.ilay.oidcserver.service.OidcConsentService;
import top.ilay.oidcserver.service.OidcIdentityService;
import top.ilay.oidcserver.service.OidcSigningService;
import top.ilay.oidcserver.service.OidcTokenService;
import top.ilay.oidcserver.util.OidcCrypto;

public abstract class OidcTestFixture {
    protected static final Duration WAIT = Duration.ofSeconds(15);
    protected DetachedStore store;
    protected OidcClientService clients;
    protected OidcConsentService consents;
    protected OidcIdentityService identity;
    protected OidcSigningService signing;
    protected OidcTokenService tokens;
    protected OidcSettings settings;
    protected ReactiveSettingFetcher fetcher;
    protected ExternalUrlSupplier external;
    protected AtomicReference<List<String>> roles;
    protected Clock clock;
    protected User user;
    protected OidcClient app;
    protected OidcConsent consent;

    @BeforeEach
    protected void setup() throws Exception {
        store = new DetachedStore(); clock = Clock.fixed(Instant.parse("2026-10-10T01:00:00Z"), ZoneOffset.UTC);
        fetcher = mock(ReactiveSettingFetcher.class); external = mock(ExternalUrlSupplier.class);
        when(external.getRaw()).thenReturn(URI.create("http://127.0.0.1:8092").toURL());
        when(fetcher.fetch("security", OidcSettings.Security.class)).thenReturn(Mono.just(new OidcSettings.Security(true)));
        when(fetcher.fetch("protocol", OidcSettings.Lifetimes.class)).thenReturn(Mono.empty());
        settings = new OidcSettings(fetcher, external);
        roles = new AtomicReference<>(List.of("member")); var roleService = mock(RoleService.class);
        when(roleService.getRolesByUsername(anyString())).thenAnswer(invocation -> Flux.fromIterable(roles.get()));
        when(roleService.listPermissions(any())).thenAnswer(invocation -> Flux.empty());
        identity = new OidcIdentityService(store.client, roleService); clients = new OidcClientService(store.client);
        consents = new OidcConsentService(store.client, clients, identity, clock);
        signing = new OidcSigningService(store.client, settings, clock);
        tokens = new OidcTokenService(store.client, clients, consents, identity, signing, settings, clock);
        user = OidcCrypto.named(new User(), "alice"); user.setSpec(new User.UserSpec()); user.getSpec().setDisplayName("小明");
        user.getSpec().setEmail("alice@example.test"); user.getSpec().setEmailVerified(true); user.getSpec().setPassword("secret-password");
        user = store.add(user);
        var role = OidcCrypto.named(new Role(), "member"); store.add(role);
        var request = new OidcClientRequest("测试应用", "说明", OidcClient.ClientType.PUBLIC, List.of("https://app.example/callback?existing=%2F"),
            List.of("openid", "profile", "email", "offline_access"), OidcClient.AccessPolicy.ROLES, List.of("member"), true);
        var response = clients.create(request).block(WAIT); app = clients.get(response.clientId()).block(WAIT);
        consent = consents.grant("alice", app, request.scopes()).block(WAIT);
    }

    protected OidcValidation.AuthorizationRequest request(String verifier) {
        return new OidcValidation.AuthorizationRequest(app.getMetadata().getName(), app.getSpec().getRedirectUris().getFirst(), consent.getSpec().getScopes(), "a&b=中文", "nonce-value", OidcCrypto.challenge(verifier), null);
    }
}
