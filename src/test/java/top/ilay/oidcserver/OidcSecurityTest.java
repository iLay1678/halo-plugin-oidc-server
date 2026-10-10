package top.ilay.oidcserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import run.halo.app.core.extension.Role;
import run.halo.app.core.extension.User;
import run.halo.app.core.user.service.RoleService;
import run.halo.app.extension.Secret;
import run.halo.app.infra.ExternalUrlSupplier;
import run.halo.app.plugin.ReactiveSettingFetcher;

class OidcSecurityTest {
    private static final Duration WAIT = Duration.ofSeconds(15);
    DetachedStore store;
    OidcClientService clients;
    OidcConsentService consents;
    OidcIdentityService identity;
    OidcSigningService signing;
    OidcTokenService tokens;
    OidcSettings settings;
    ReactiveSettingFetcher fetcher;
    ExternalUrlSupplier external;
    AtomicReference<List<String>> roles;
    Clock clock;
    User user;
    OidcClient app;
    OidcConsent consent;

    @BeforeEach void setup() throws Exception {
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
    private OidcValidation.AuthorizationRequest request(String verifier) {
        return new OidcValidation.AuthorizationRequest(app.getMetadata().getName(), app.getSpec().getRedirectUris().getFirst(), consent.getSpec().getScopes(), "a&b=中文", "nonce-value", OidcCrypto.challenge(verifier), null);
    }
    private Mono<Map<String, Object>> issue() {
        var verifier = OidcCrypto.random(); var request = request(verifier);
        return tokens.authorize(request, app, consent).flatMap(code -> tokens.exchange(app, code, request.redirectUri(), verifier));
    }
    @Test void redirectsAndPkceRejectUnsafeInputs() {
        for (var raw : List.of("https://app.example/cb#x", "http://app.example/cb", "//app.example/cb", "https://user@app.example/cb", "https://*.example/cb", "http://localhost.evil/cb")) {
            assertThatThrownBy(() -> OidcValidation.redirect(raw)).isInstanceOf(OAuthError.class);
        }
        for (var raw : List.of("https://app.example/cb", "http://localhost:8092/cb", "http://127.0.0.1/cb", "http://[::1]/cb")) { assertThat(OidcValidation.redirect(raw)).isNotNull(); }
        assertThatThrownBy(() -> OidcValidation.verifier("short", OidcCrypto.challenge("short"))).isInstanceOf(OAuthError.class);
        var params = params(); params.set("code_challenge_method", "plain");
        assertThatThrownBy(() -> OidcValidation.authorization(params, app)).isInstanceOf(OAuthError.class);
        var withoutPkce = params(); withoutPkce.remove("code_challenge"); withoutPkce.remove("code_challenge_method");
        assertThatThrownBy(() -> OidcValidation.authorization(withoutPkce, app)).isInstanceOf(OAuthError.class);
        var mismatch = params(); mismatch.set("redirect_uri", "https://app.example/callback?existing=/");
        assertThatThrownBy(() -> OidcValidation.authorization(mismatch, app)).isInstanceOf(OAuthError.class);
    }
    @Test void authorizationRejectsScopesDuplicateParametersAndUnsupportedPrompts() {
        for (var pair : List.of(Map.entry("scope", "email"), Map.entry("scope", "openid unknown"), Map.entry("prompt", "login"), Map.entry("prompt", "none consent"), Map.entry("max_age", "10"), Map.entry("nonce", ""))) {
            var input = params(); input.set(pair.getKey(), pair.getValue()); assertThatThrownBy(() -> OidcValidation.authorization(input, app)).isInstanceOf(OAuthError.class);
        }
        var duplicate = params(); duplicate.add("client_id", app.getMetadata().getName());
        assertThatThrownBy(() -> OidcValidation.authorization(duplicate, app)).isInstanceOf(OAuthError.class);
        var input = params(); input.set("prompt", "consent"); assertThat(OidcValidation.authorization(input, app).prompt()).isEqualTo("consent");
    }
    @Test void authorizationCodeCasAllowsOnlyOneConcurrentExchange() {
        var verifier = OidcCrypto.random(); var request = request(verifier); var code = tokens.authorize(request, app, consent).block(WAIT);
        store.synchronizeFetch(OidcAuthorizationCode.class, "code-" + OidcCrypto.digest(code));
        var one = tokens.exchange(app, code, request.redirectUri(), verifier).materialize();
        var two = tokens.exchange(app, code, request.redirectUri(), verifier).materialize();
        StepVerifier.create(Mono.zip(one, two)).assertNext(pair -> {
            assertThat(List.of(pair.getT1(), pair.getT2()).stream().filter(signal -> signal.hasValue()).count()).isEqualTo(1);
            assertThat(List.of(pair.getT1(), pair.getT2()).stream().filter(signal -> signal.isOnError()).count()).isEqualTo(1);
        }).verifyComplete();
        StepVerifier.create(tokens.exchange(app, code, request.redirectUri(), verifier)).expectError(OAuthError.class).verify(WAIT);
    }
    @Test void pkceAndWrongClientDoNotConsumeAuthorizationCode() {
        var verifier = OidcCrypto.random(); var request = request(verifier); var code = tokens.authorize(request, app, consent).block(WAIT);
        StepVerifier.create(tokens.exchange(app, code, request.redirectUri(), OidcCrypto.random())).expectError(OAuthError.class).verify(WAIT);
        assertThat(store.snapshot(OidcAuthorizationCode.class, "code-" + OidcCrypto.digest(code)).getSpec().isConsumed()).isFalse();
        StepVerifier.create(tokens.exchange(app, code, request.redirectUri(), verifier)).expectNextCount(1).verifyComplete();
    }
    @Test void refreshReplayRevokesAllAccessAndRefreshTokens() {
        var initial = issue().block(WAIT); var oldRefresh = (String) initial.get("refresh_token");
        var rotated = tokens.refresh(app, oldRefresh, null).block(WAIT);
        StepVerifier.create(tokens.refresh(app, oldRefresh, null)).expectError(OAuthError.class).verify(WAIT);
        for (var token : List.of(initial.get("access_token"), rotated.get("access_token"))) {
            StepVerifier.create(tokens.userinfo((String) token)).expectError(OAuthError.class).verify(WAIT);
        }
        StepVerifier.create(tokens.refresh(app, (String) rotated.get("refresh_token"), null)).expectError(OAuthError.class).verify(WAIT);
    }
    @Test void refreshScopeReductionStillRotatesAndReturnsRefreshToken() {
        var initial = issue().block(WAIT);
        var rotated = tokens.refresh(app, (String) initial.get("refresh_token"), "openid").block(WAIT);
        assertThat(rotated).containsKey("refresh_token").containsEntry("scope", "openid");
        assertThat(rotated.get("refresh_token")).isNotEqualTo(initial.get("refresh_token"));
        StepVerifier.create(tokens.refresh(app, (String) rotated.get("refresh_token"), null))
            .expectNextCount(1).verifyComplete();
        StepVerifier.create(tokens.refresh(app, (String) initial.get("refresh_token"), null))
            .expectError(OAuthError.class).verify(WAIT);
    }
    @Test void revokeUnknownExpiredAndCrossClientTokensAreIdempotent() {
        StepVerifier.create(tokens.revoke(app, "unknown-token")).verifyComplete();
        StepVerifier.create(tokens.revoke(app, " ")).verifyComplete();
        var otherRequest = new OidcClientRequest("另一个应用", "", OidcClient.ClientType.PUBLIC,
            List.of("https://other.example/callback"), List.of("openid"), OidcClient.AccessPolicy.ALL, List.of(), true);
        var other = clients.create(otherRequest).block(WAIT);
        var otherClient = clients.get(other.clientId()).block(WAIT);
        var verifier = OidcCrypto.random();
        var otherConsent = consents.grant("alice", otherClient, List.of("openid")).block(WAIT);
        var otherAuth = new OidcValidation.AuthorizationRequest(otherClient.getMetadata().getName(),
            otherClient.getSpec().getRedirectUris().getFirst(), List.of("openid"), null, null, OidcCrypto.challenge(verifier), null);
        var token = tokens.authorize(otherAuth, otherClient, otherConsent)
            .flatMap(code -> tokens.exchange(otherClient, code, otherAuth.redirectUri(), verifier)).block(WAIT);
        StepVerifier.create(tokens.revoke(app, (String) token.get("access_token"))).verifyComplete();
        StepVerifier.create(tokens.userinfo((String) token.get("access_token"))).expectNextCount(1).verifyComplete();
    }
    @Test void concurrentRefreshReplayCannotEscapeFamilyRevocation() {
        var initial = issue().block(WAIT); var raw = (String) initial.get("refresh_token");
        var state = store.snapshot(OidcToken.class, "token-" + OidcCrypto.digest(raw));
        store.synchronizeFetch(OidcTokenFamily.class, state.getSpec().getFamilyName());
        var result = Mono.zip(tokens.refresh(app, raw, null).materialize(), tokens.refresh(app, raw, null).materialize()).block(WAIT);
        assertThat(store.snapshot(OidcTokenFamily.class, state.getSpec().getFamilyName()).getSpec().isRevoked()).isTrue();
        for (var signal : List.of(result.getT1(), result.getT2())) {
            if (signal.hasValue()) { StepVerifier.create(tokens.userinfo((String) signal.get().get("access_token"))).expectError(OAuthError.class).verify(WAIT); }
        }
    }
    @Test void consentOwnershipAndNewEpochInvalidateHistoricalTokens() {
        var initial = issue().block(WAIT);
        StepVerifier.create(consents.revoke(consent.getMetadata().getName(), "bob")).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(tokens.userinfo((String) initial.get("access_token"))).assertNext(claims -> assertThat(claims).containsEntry("preferred_username", "alice")).verifyComplete();
        consents.revoke(consent.getMetadata().getName(), "alice").block(WAIT);
        var fresh = consents.grant("alice", app, consent.getSpec().getScopes()).block(WAIT);
        assertThat(fresh.getSpec().getAuthorizationVersion()).isNotEqualTo(consent.getSpec().getAuthorizationVersion());
        StepVerifier.create(tokens.userinfo((String) initial.get("access_token"))).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(tokens.refresh(app, (String) initial.get("refresh_token"), null)).expectError(OAuthError.class).verify(WAIT);
    }
    @Test void roleRemovalDisabledUserAndClientEpochFailClosed() {
        var initial = issue().block(WAIT); roles.set(List.of("super-role"));
        StepVerifier.create(tokens.refresh(app, (String) initial.get("refresh_token"), null)).expectError(OAuthError.class).verify(WAIT);
        roles.set(List.of("member")); clients.state(app.getMetadata().getName(), false, false).block(WAIT);
        clients.state(app.getMetadata().getName(), true, false).block(WAIT);
        StepVerifier.create(tokens.userinfo((String) initial.get("access_token"))).expectError(OAuthError.class).verify(WAIT);
        var latest = store.snapshot(User.class, "alice"); latest.getSpec().setDisabled(true); store.save(latest, true);
        StepVerifier.create(identity.allowed(app, "alice")).expectError(OAuthError.class).verify(WAIT);
    }
    @Test void clientSecretsOnlyPersistAsDigestsAndTypeCannotChange() {
        var response = clients.create(new OidcClientRequest("机密应用", "", OidcClient.ClientType.CONFIDENTIAL, List.of("https://app.example/cb"), List.of("openid"), OidcClient.AccessPolicy.ALL, List.of(), true)).block(WAIT);
        var secret = response.clientSecret(); var stored = clients.get(response.clientId()).block(WAIT);
        var hidden = store.snapshot(Secret.class, stored.getSpec().getSecretRef());
        assertThat(hidden.getData().get("digest")).isEqualTo(OidcCrypto.hash(secret));
        assertThat(store.mapper.valueToTree(stored).toString()).doesNotContain(secret);
        assertThat(OidcClientResponse.of(stored, null).clientSecret()).isNull();
        StepVerifier.create(clients.authenticate(response.clientId(), secret, true)).expectNextCount(1).verifyComplete();
        StepVerifier.create(clients.authenticate(response.clientId(), "bad", true)).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(clients.authenticate(app.getMetadata().getName(), secret, true)).expectError(OAuthError.class).verify(WAIT);
        clients.reset(response.clientId()).block(WAIT);
        StepVerifier.create(clients.authenticate(response.clientId(), secret, true)).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(clients.update(response.clientId(), new OidcClientRequest("更改", "", OidcClient.ClientType.PUBLIC, List.of("https://app.example/cb"), List.of("openid"), OidcClient.AccessPolicy.ALL, List.of(), true)))
            .expectError(OAuthError.class).verify(WAIT);
    }
    @Test void confidentialClientMayExchangeAuthorizationCodeWithoutPkce() {
        var created = clients.create(new OidcClientRequest("无 PKCE 机密应用", "", OidcClient.ClientType.CONFIDENTIAL,
            List.of("https://app.example/cb"), List.of("openid"), OidcClient.AccessPolicy.ALL, List.of(), true)).block(WAIT);
        var confidential = clients.get(created.clientId()).block(WAIT);
        var granted = consents.grant("alice", confidential, List.of("openid")).block(WAIT);
        var request = new OidcValidation.AuthorizationRequest(confidential.getMetadata().getName(), "https://app.example/cb",
            List.of("openid"), "state", null, null, null);
        var code = tokens.authorize(request, confidential, granted).block(WAIT);
        StepVerifier.create(tokens.exchange(confidential, code, request.redirectUri(), null)).expectNextCount(1).verifyComplete();
    }
    @Test void jwtJwksPersistAndExposeOnlyScopedClaims() throws Exception {
        var initial = issue().block(WAIT); var jwt = SignedJWT.parse((String) initial.get("id_token"));
        var keys = (List<Map<String, Object>>) signing.jwks().block(WAIT).get("keys"); var jwk = RSAKey.parse(keys.getFirst());
        assertThat(jwk.isPrivate()).isFalse(); assertThat(keys.getFirst()).doesNotContainKeys("d", "p", "q", "dp", "dq", "qi");
        assertThat(jwt.verify(new RSASSAVerifier(jwk))).isTrue(); assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(settings.issuer());
        assertThat(jwt.getJWTClaimsSet().getClaim("nonce")).isEqualTo("nonce-value");
        assertThat(jwt.getJWTClaimsSet().getClaim("at_hash")).isEqualTo(OidcCrypto.atHash((String) initial.get("access_token")));
        assertThat(jwt.getJWTClaimsSet().getClaims()).doesNotContainKeys("password", "phone", "totpEncryptedSecret");
        var restarted = new OidcSigningService(store.client, settings, clock); assertThat(restarted.jwks().block(WAIT)).isEqualTo(signing.jwks().block(WAIT));
    }
    @Test void malformedPersistedSigningKeyIsRejectedAndNeverUsedAsFallback() {
        var secret = OidcCrypto.named(new Secret(), "oidc-server-signing-key");
        secret.setType(Secret.SECRET_TYPE_OPAQUE); secret.setData(Map.of("jwk", "not-a-jwk".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        store.add(secret);
        var broken = new OidcSigningService(store.client, settings, clock);
        StepVerifier.create(broken.jwks()).expectError().verify(WAIT);
    }
    @Test void issuerChangesAndDisabledSettingsRejectExistingTokens() throws Exception {
        var initial = issue().block(WAIT); when(external.getRaw()).thenReturn(URI.create("https://new.example").toURL());
        StepVerifier.create(tokens.userinfo((String) initial.get("access_token"))).expectError(OAuthError.class).verify(WAIT);
        when(external.getRaw()).thenReturn(null); assertThatThrownBy(settings::issuer).isInstanceOf(IllegalStateException.class);
        when(fetcher.fetch("security", OidcSettings.Security.class)).thenReturn(Mono.empty());
        StepVerifier.create(settings.enabled()).expectError(OAuthError.class).verify(WAIT);
        when(fetcher.fetch("security", OidcSettings.Security.class)).thenReturn(Mono.error(new IllegalStateException("配置不可用")));
        StepVerifier.create(settings.enabled()).expectError(IllegalStateException.class).verify(WAIT);
    }
    @Test void scopeCannotExpandAndOfflineAccessRequiresConsent() {
        var onlyOpenid = consents.grant("alice", app, List.of("openid")).block(WAIT); var verifier = OidcCrypto.random();
        var req = new OidcValidation.AuthorizationRequest(app.getMetadata().getName(), app.getSpec().getRedirectUris().getFirst(), List.of("openid"), null, null, OidcCrypto.challenge(verifier), null);
        var response = tokens.authorize(req, app, onlyOpenid).flatMap(code -> tokens.exchange(app, code, req.redirectUri(), verifier)).block(WAIT);
        assertThat(response).doesNotContainKey("refresh_token");
        consent = consents.grant("alice", app, List.of("openid", "offline_access")).block(WAIT); var issued = issue().block(WAIT);
        StepVerifier.create(tokens.refresh(app, (String) issued.get("refresh_token"), "openid offline_access email")).expectError(OAuthError.class).verify(WAIT);
    }
    @Test void callbackPreservesRegisteredQueryAndSafelyEncodesState() {
        var callback = OidcAuthorizationController.callback(request(OidcCrypto.random()), "code", "opaque-code");
        assertThat(callback.getHeaders().getLocation().toASCIIString()).contains("existing=%2F&code=opaque-code&state=a%26b%3D%E4%B8%AD%E6%96%87");
    }
    @Test void loginTargetSafelyEncodesNestedAuthorizationQuery() {
        var original = "/oidc/authorize?scope=openid+profile+email&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=a%26b";
        var target = OidcAuthorizationController.loginTarget(original);
        assertThat(target).isEqualTo("/login?redirect_uri=%2Foidc%2Fauthorize%3Fscope%3Dopenid%2Bprofile%2Bemail%26redirect_uri%3Dhttps%253A%252F%252Fapp.example%252Fcallback%26state%3Da%2526b");
        assertThat(java.net.URI.create(target)).isNotNull();
        assertThat(java.net.URLDecoder.decode(target.substring(target.indexOf('=') + 1), java.nio.charset.StandardCharsets.UTF_8))
            .isEqualTo(original);
    }
    @Test void consentHeadersAllowOnlyTheRegisteredCallbackOrigin() {
        var headers = OidcAuthorizationController.consentHeaders(request(OidcCrypto.random()));
        assertThat(headers.getFirst("Content-Security-Policy"))
            .contains("form-action 'self' https://app.example;").doesNotContain("form-action *");
    }
    @Test void anonymousAuthorizationRedirectPreservesRawQueryAndSilentPrompt() {
        var original = authorizationPath("openid+profile+email") + "&access_type=offline&state=a%2Bb%26%E4%B8%AD%E6%96%87";
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET, URI.create(original)));
        var response = authorization().authorize(exchange).block(WAIT);
        assertThat(response.getStatusCode().value()).isEqualTo(302);
        var target = response.getHeaders().getLocation().toASCIIString();
        var restored = java.net.URLDecoder.decode(target.substring(target.indexOf('=') + 1), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(restored).isEqualTo(original);
        var silent = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET, URI.create(original + "&prompt=none")));
        var result = authorization().authorize(silent).block(WAIT);
        assertThat(result.getHeaders().getLocation().toString()).contains("error=login_required").doesNotContain("/login?");
    }
    @Test void consentDecisionsRedirectAndConsumePendingRequest() {
        var auth = new TestingAuthenticationToken("alice", ""); auth.setAuthenticated(true);
        for (var decision : List.of("allow", "deny")) {
            var controller = authorization();
            var exchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET,
                URI.create(authorizationPath("openid+profile") + "&prompt=consent&state=browser-state")));
            exchange.getAttributes().put(CsrfToken.class.getName(), Mono.just(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "csrf-value")));
            var page = controller.authorize(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)).block(WAIT);
            assertThat(page.getStatusCode().value()).isEqualTo(200);
            var matcher = java.util.regex.Pattern.compile("name=\"request_id\" value=\"([^\"]+)\"").matcher((String) page.getBody());
            assertThat(matcher.find()).isTrue();
            var session = exchange.getSession().block(WAIT);
            var submission = MockServerWebExchange.builder(MockServerHttpRequest.post("/oidc/authorize")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("request_id=" + matcher.group(1) + "&decision=" + decision))
                .sessionManager(ignored -> Mono.just(session)).build();
            var result = controller.decide(submission).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)).block(WAIT);
            assertThat(result.getStatusCode().value()).isEqualTo(302);
            assertThat(result.getHeaders().getLocation().toString()).startsWith("https://app.example/callback?existing=%2F&")
                .contains(decision.equals("allow") ? "code=" : "error=access_denied", "state=browser-state");
            var replay = controller.decide(submission).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)).block(WAIT);
            assertThat(replay.getStatusCode().value()).isEqualTo(400);
        }
    }
    @Test void unauthorizedUserSeesConsentPageWithAccessWarningAndCannotAllow() {
        roles.set(List.of("other-role"));
        var auth = new TestingAuthenticationToken("alice", ""); auth.setAuthenticated(true);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET,
            URI.create(authorizationPath("openid+profile") + "&prompt=consent")));
        exchange.getAttributes().put(CsrfToken.class.getName(), Mono.just(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "csrf-value")));
        var controller = authorization();
        var page = controller.authorize(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)).block(WAIT);
        assertThat(page.getStatusCode().value()).isEqualTo(200);
        assertThat((String) page.getBody()).contains("当前用户没有访问该应用的权限", "返回应用")
            .doesNotContain("同意并继续");
        var matcher = java.util.regex.Pattern.compile("name=\"request_id\" value=\"([^\"]+)\"").matcher((String) page.getBody());
        assertThat(matcher.find()).isTrue();
        var session = exchange.getSession().block(WAIT);
        var submission = MockServerWebExchange.builder(MockServerHttpRequest.post("/oidc/authorize")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("request_id=" + matcher.group(1) + "&decision=allow"))
            .sessionManager(ignored -> Mono.just(session)).build();
        var result = controller.decide(submission).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)).block(WAIT);
        assertThat(result.getStatusCode().value()).isEqualTo(302);
        assertThat(result.getHeaders().getLocation().toString()).contains("error=access_denied");
    }
    @Test void consentPageEscapesUntrustedTextWithoutReplacingTokenPlaceholders() {
        app.getSpec().setDisplayName("<script>__CSRF_TOKEN__ & %1$s</script>");
        app.getSpec().setDescription("\" onload=\"bad");
        var html = OidcConsentPage.render(request(OidcCrypto.random()), app, "alice", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "csrf-secret"), "request-id");
        assertThat(html).contains("&lt;script&gt;__CSRF_TOKEN__ &amp; %1$s&lt;/script&gt;")
            .contains("name=\"_csrf\" value=\"csrf-secret\"")
            .doesNotContain("<script>");
    }
    private OidcAuthorizationController authorization() {
        return new OidcAuthorizationController(settings, clients, consents, identity, tokens, signing, clock);
    }
    private String authorizationPath(String scopes) {
        return "/oidc/authorize?client_id=" + app.getMetadata().getName()
            + "&redirect_uri=" + java.net.URLEncoder.encode(app.getSpec().getRedirectUris().getFirst(), java.nio.charset.StandardCharsets.UTF_8)
            + "&response_type=code&scope=" + scopes + "&code_challenge=" + OidcCrypto.challenge(OidcCrypto.random()) + "&code_challenge_method=S256";
    }
    @Test void fullAuthenticationIsRequired() {
        var unfinished = new TestingAuthenticationToken("alice", ""); unfinished.setAuthenticated(false);
        assertThat(OidcIdentityService.complete(unfinished)).isFalse();
        unfinished.setAuthenticated(true); assertThat(OidcIdentityService.complete(unfinished)).isTrue();
    }
    @Test void protocolFilterMatchesOnlyExactPathsAndSetsErrors() {
        var filter = new OidcProtocolFilter(clients, tokens); var delegated = new java.util.concurrent.atomic.AtomicBoolean();
        WebFilterChain chain = exchange -> { delegated.set(true); return Mono.empty(); };
        StepVerifier.create(filter.filter(MockServerWebExchange.from(MockServerHttpRequest.post("/oidc/token/extra")), chain)).verifyComplete();
        assertThat(delegated).isTrue(); delegated.set(false);
        var request = MockServerWebExchange.from(MockServerHttpRequest.get("/oidc/userinfo").header("Authorization", "Bearer unknown"));
        StepVerifier.create(filter.filter(request, chain)).verifyComplete();
        assertThat(delegated).isFalse(); assertThat(request.getResponse().getStatusCode().value()).isEqualTo(401);
        assertThat(request.getResponse().getHeaders().getFirst("WWW-Authenticate")).contains("invalid_token");
        assertThat(request.getResponse().getHeaders().getCacheControl()).isEqualTo("no-store");
    }
    @Test void authorizationSchemesAreCaseInsensitiveButRequireWhitespace() {
        assertThat(OidcProtocolFilter.hasScheme("Bearer token", "Bearer")).isTrue();
        assertThat(OidcProtocolFilter.hasScheme("bEaReR token", "Bearer")).isTrue();
        assertThat(OidcProtocolFilter.hasScheme("Basic abc", "Basic")).isTrue();
        assertThat(OidcProtocolFilter.hasScheme("bearertoken", "Bearer")).isFalse();
        assertThat(OidcProtocolFilter.hasScheme("Bearer", "Bearer")).isFalse();
    }
    private LinkedMultiValueMap<String, String> params() {
        var params = new LinkedMultiValueMap<String, String>(); params.set("client_id", app.getMetadata().getName());
        params.set("redirect_uri", app.getSpec().getRedirectUris().getFirst()); params.set("response_type", "code"); params.set("scope", "openid profile");
        params.set("code_challenge_method", "S256"); params.set("code_challenge", OidcCrypto.challenge(OidcCrypto.random())); return params;
    }
}
