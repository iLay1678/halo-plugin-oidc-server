package top.ilay.oidcserver.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import run.halo.app.core.extension.User;
import run.halo.app.extension.Secret;
import top.ilay.oidcserver.config.OidcSettings;
import top.ilay.oidcserver.dto.OidcClientRequest;
import top.ilay.oidcserver.dto.OidcClientResponse;
import top.ilay.oidcserver.extension.OidcAuthorizationCode;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.extension.OidcToken;
import top.ilay.oidcserver.extension.OidcTokenFamily;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.protocol.OidcValidation;
import top.ilay.oidcserver.support.OidcTestFixture;
import top.ilay.oidcserver.util.OidcCrypto;

class OidcSecurityTest extends OidcTestFixture {
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
        var otherConsent = consents.grant(user, otherClient, List.of("openid")).block(WAIT);
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
        var bob = OidcCrypto.named(new User(), "bob"); bob.setSpec(new User.UserSpec()); bob = store.add(bob);
        StepVerifier.create(consents.revoke(consent.getMetadata().getName(), bob)).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(tokens.userinfo((String) initial.get("access_token"))).assertNext(claims -> assertThat(claims).containsEntry("preferred_username", "alice")).verifyComplete();
        consents.revoke(consent.getMetadata().getName(), user).block(WAIT);
        var fresh = consents.grant(user, app, consent.getSpec().getScopes()).block(WAIT);
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
        var granted = consents.grant(user, confidential, List.of("openid")).block(WAIT);
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
        var onlyOpenid = consents.grant(user, app, List.of("openid")).block(WAIT); var verifier = OidcCrypto.random();
        var req = new OidcValidation.AuthorizationRequest(app.getMetadata().getName(), app.getSpec().getRedirectUris().getFirst(), List.of("openid"), null, null, OidcCrypto.challenge(verifier), null);
        var response = tokens.authorize(req, app, onlyOpenid).flatMap(code -> tokens.exchange(app, code, req.redirectUri(), verifier)).block(WAIT);
        assertThat(response).doesNotContainKey("refresh_token");
        consent = consents.grant(user, app, List.of("openid", "offline_access")).block(WAIT); var issued = issue().block(WAIT);
        StepVerifier.create(tokens.refresh(app, (String) issued.get("refresh_token"), "openid offline_access email")).expectError(OAuthError.class).verify(WAIT);
    }

    @Test void fullAuthenticationIsRequired() {
        var unfinished = new TestingAuthenticationToken("alice", ""); unfinished.setAuthenticated(false);
        assertThat(OidcIdentityService.complete(unfinished)).isFalse();
        unfinished.setAuthenticated(true); assertThat(OidcIdentityService.complete(unfinished)).isTrue();
    }
    private Mono<Map<String, Object>> issue() {
        var verifier = OidcCrypto.random(); var request = request(verifier);
        return tokens.authorize(request, app, consent).flatMap(code -> tokens.exchange(app, code, request.redirectUri(), verifier));
    }

    private LinkedMultiValueMap<String, String> params() {
        var params = new LinkedMultiValueMap<String, String>(); params.set("client_id", app.getMetadata().getName());
        params.set("redirect_uri", app.getSpec().getRedirectUris().getFirst()); params.set("response_type", "code"); params.set("scope", "openid profile");
        params.set("code_challenge_method", "S256"); params.set("code_challenge", OidcCrypto.challenge(OidcCrypto.random())); return params;
    }
}
