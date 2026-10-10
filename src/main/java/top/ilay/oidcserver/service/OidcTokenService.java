package top.ilay.oidcserver.service;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.User;
import run.halo.app.extension.ReactiveExtensionClient;
import top.ilay.oidcserver.config.OidcSettings;
import top.ilay.oidcserver.extension.GrantBinding;
import top.ilay.oidcserver.extension.OidcAuthorizationCode;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.extension.OidcToken;
import top.ilay.oidcserver.extension.OidcTokenFamily;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.protocol.OidcValidation;
import top.ilay.oidcserver.protocol.OidcValidation.AuthorizationRequest;
import top.ilay.oidcserver.util.ExtensionUtils;
import top.ilay.oidcserver.util.OidcCrypto;

@Service
@RequiredArgsConstructor
public class OidcTokenService {
    private final ReactiveExtensionClient store;
    private final OidcClientService clients;
    private final OidcConsentService consents;
    private final OidcIdentityService identities;
    private final OidcSigningService signing;
    private final OidcSettings settings;
    private final Clock clock;

    public Mono<String> authorize(AuthorizationRequest request, OidcClient client, OidcConsent consent) {
        return settings.enabled().then(settings.lifetimes()).flatMap(lifetime -> Mono.defer(() -> {
            var raw = OidcCrypto.random(); var code = OidcCrypto.named(new OidcAuthorizationCode(), "code-" + OidcCrypto.digest(raw));
            var spec = new OidcAuthorizationCode.Spec(); binding(spec, client, consent, request.scopes());
            spec.setIssuer(settings.issuer());
            spec.setExpiresAt(clock.instant().plusSeconds(lifetime.codeSeconds())); spec.setRedirectUri(request.redirectUri());
            spec.setChallenge(request.challenge()); spec.setNonce(request.nonce()); code.setSpec(spec);
            return store.create(code).thenReturn(raw);
        }));
    }
    static void binding(GrantBinding spec, OidcClient client, OidcConsent consent, List<String> scopes) {
        spec.setClientId(client.getMetadata().getName()); spec.setClientVersion(client.getSpec().getSecurityVersion());
        spec.setUsername(consent.getSpec().getUsername()); spec.setConsentName(consent.getMetadata().getName());
        spec.setSubject(consent.getSpec().getSubject());
        spec.setConsentVersion(consent.getSpec().getAuthorizationVersion()); spec.setScopes(List.copyOf(scopes));
    }
    public Mono<Map<String, Object>> exchange(OidcClient authenticated, String raw, String redirect, String verifier) {
        return settings.enabled().then(store.fetch(OidcAuthorizationCode.class, "code-" + OidcCrypto.digest(safeToken(raw))))
            .filter(ExtensionUtils::active).switchIfEmpty(Mono.error(OAuthError.grant())).flatMap(code -> {
                var spec = code.getSpec();
                if (spec.isConsumed() || !authenticated.getMetadata().getName().equals(spec.getClientId())
                    || !java.util.Objects.equals(redirect, spec.getRedirectUri())) { return Mono.error(OAuthError.grant()); }
                if (authenticated.getSpec().getClientType() == OidcClient.ClientType.PUBLIC && spec.getChallenge() == null) {
                    return Mono.error(OAuthError.grant());
                }
                OidcValidation.verifier(verifier, spec.getChallenge());
                return valid(spec).flatMap(valid -> {
                    // 授权码只允许一次版本更新；冲突直接拒绝，不重试消费。
                    spec.setConsumed(true);
                    return store.update(code).onErrorMap(OptimisticLockingFailureException.class, error -> OAuthError.grant())
                        .then(settings.lifetimes()).flatMap(lifetime -> newFamily(spec, lifetime)
                            .flatMap(family -> issue(spec, family, valid.user(), spec.getNonce(), lifetime, null, false)));
                });
            });
    }
    private Mono<OidcTokenFamily> newFamily(GrantBinding binding, OidcSettings.Lifetimes lifetime) {
        var family = OidcCrypto.named(new OidcTokenFamily(), "family-" + OidcCrypto.digest(OidcCrypto.random()));
        var spec = new OidcTokenFamily.Spec(); OidcCrypto.copy(binding, spec);
        spec.setExpiresAt(clock.instant().plus(binding.getScopes().contains("offline_access") ? lifetime.refreshDays() : 1, ChronoUnit.DAYS));
        family.setSpec(spec); return store.create(family);
    }
    private Mono<Map<String, Object>> issue(GrantBinding binding, OidcTokenFamily family, User user, String nonce,
        OidcSettings.Lifetimes lifetime, String nextRefresh, boolean rotateRefresh) {
        var access = OidcCrypto.random();
        // 令牌族一旦存在刷新令牌，轮换时即使请求缩减 scope 也必须返回新的刷新令牌。
        var refresh = rotateRefresh || binding.getScopes().contains("offline_access")
            ? (nextRefresh == null ? OidcCrypto.random() : nextRefresh) : null;
        Mono<OidcTokenFamily> ready;
        if (refresh != null && nextRefresh == null) {
            family.getSpec().setCurrentRefreshDigest(OidcCrypto.digest(refresh));
            ready = store.update(family);
        } else { ready = Mono.just(family); }
        return ready.flatMap(current -> token(access, OidcToken.TokenType.ACCESS, binding, current, clock.instant().plusSeconds(lifetime.accessSeconds()))
            .then(refresh == null ? Mono.empty() : token(refresh, OidcToken.TokenType.REFRESH, binding, current, current.getSpec().getExpiresAt()).then())
            .then(valid(binding)).then(family(current.getMetadata().getName()))
            .then(signing.sign(user, binding.getScopes(), binding.getClientId(), nonce, access, lifetime.idSeconds()))
            .map(id -> {
                var result = new LinkedHashMap<String, Object>(); result.put("access_token", access); result.put("token_type", "Bearer");
                result.put("expires_in", lifetime.accessSeconds()); result.put("id_token", id); result.put("scope", String.join(" ", binding.getScopes()));
                if (refresh != null) { result.put("refresh_token", refresh); }
                return (Map<String, Object>) result;
            }))
            // CAS 后任一签发步骤失败时立即撤销整个族，避免族保持可用但 currentRefreshDigest 指向未返回的令牌。
            .onErrorResume(error -> revokeFamily(family.getMetadata().getName(), 8).then(Mono.error(error)));
    }
    private Mono<OidcToken> token(String raw, OidcToken.TokenType type, GrantBinding binding, OidcTokenFamily family, java.time.Instant expiry) {
        var value = OidcCrypto.named(new OidcToken(), "token-" + OidcCrypto.digest(raw));
        var spec = new OidcToken.Spec(); OidcCrypto.copy(binding, spec); spec.setExpiresAt(expiry);
        spec.setTokenType(type); spec.setFamilyName(family.getMetadata().getName()); value.setSpec(spec);
        return store.create(value);
    }
    public Mono<Map<String, Object>> refresh(OidcClient authenticated, String raw, String requestedScopes) {
        var digest = OidcCrypto.digest(safeToken(raw));
        return settings.enabled().then(store.fetch(OidcToken.class, "token-" + digest))
            .filter(value -> value.getSpec().getTokenType() == OidcToken.TokenType.REFRESH)
            .filter(value -> authenticated.getMetadata().getName().equals(value.getSpec().getClientId()))
            .switchIfEmpty(Mono.error(OAuthError.grant())).flatMap(token -> {
                var spec = token.getSpec();
                var scopes = requestedScopes == null ? spec.getScopes() : OidcValidation.scopes(requestedScopes);
                if (!spec.getScopes().containsAll(scopes)) { return Mono.error(new OAuthError("invalid_scope", "刷新不能扩大授权范围")); }
                return family(spec.getFamilyName()).flatMap(family -> {
                    if (spec.isRevoked() || !digest.equals(family.getSpec().getCurrentRefreshDigest())) {
                        return revokeFamily(spec.getFamilyName(), 8).then(Mono.error(OAuthError.grant()));
                    }
                    return valid(spec).flatMap(valid -> {
                        var next = OidcCrypto.random();
                        family.getSpec().setCurrentRefreshDigest(OidcCrypto.digest(next));
                        // 所有轮换与全族撤销共用同一 CAS，不能以子令牌状态替代。
                        return store.update(family).onErrorResume(OptimisticLockingFailureException.class, error ->
                            revokeFamily(spec.getFamilyName(), 8).then(Mono.error(OAuthError.grant())))
                            .flatMap(updated -> settings.lifetimes().flatMap(lifetime -> {
                                spec.setScopes(scopes); return issue(spec, updated, valid.user(), null, lifetime, next, true);
                            }).onErrorResume(error -> revokeFamily(spec.getFamilyName(), 8).then(Mono.error(error))));
                    });
                });
            });
    }
    private Mono<ValidGrant> valid(GrantBinding binding) {
        if (binding.getExpiresAt() == null || !binding.getExpiresAt().isAfter(clock.instant())) { return Mono.error(OAuthError.grant()); }
        if (!java.util.Objects.equals(settings.issuer(), binding.getIssuer())) { return Mono.error(OAuthError.grant()); }
        return clients.enabled(binding.getClientId()).filter(client -> client.getSpec().getSecurityVersion() == binding.getClientVersion())
            .switchIfEmpty(Mono.error(OAuthError.grant())).flatMap(client -> consents.validate(binding)
                .then(identities.allowed(client, binding.getUsername()))
                .filter(user -> OidcIdentityService.subject(user).equals(binding.getSubject()))
                .switchIfEmpty(Mono.error(OAuthError.grant())).map(user -> new ValidGrant(client, user)));
    }
    private Mono<OidcTokenFamily> family(String name) {
        return store.fetch(OidcTokenFamily.class, name).filter(ExtensionUtils::active)
            .filter(value -> !value.getSpec().isRevoked() && value.getSpec().getExpiresAt().isAfter(clock.instant()))
            .switchIfEmpty(Mono.error(OAuthError.grant()));
    }
    public Mono<Map<String, Object>> userinfo(String raw) {
        return settings.enabled().then(find(raw)).filter(token -> token.getSpec().getTokenType() == OidcToken.TokenType.ACCESS)
            .switchIfEmpty(Mono.error(OAuthError.token())).flatMap(token -> family(token.getSpec().getFamilyName())
                .then(valid(token.getSpec())).map(valid -> OidcIdentityService.claims(valid.user(), token.getSpec().getScopes())))
            .switchIfEmpty(Mono.error(OAuthError.token()))
            .onErrorMap(OAuthError.class, error -> "temporarily_unavailable".equals(error.code()) ? error : OAuthError.token());
    }
    public Mono<Map<String, Object>> introspect(OidcClient authenticated, String raw) {
        if (authenticated.getSpec().getClientType() != OidcClient.ClientType.CONFIDENTIAL) { return Mono.error(OAuthError.client()); }
        return settings.enabled().then(find(raw)).filter(token -> authenticated.getMetadata().getName().equals(token.getSpec().getClientId()))
            .flatMap(token -> family(token.getSpec().getFamilyName()).filter(family -> token.getSpec().getTokenType() != OidcToken.TokenType.REFRESH
                    || OidcCrypto.digest(raw).equals(family.getSpec().getCurrentRefreshDigest()))
                .flatMap(family -> valid(token.getSpec())).map(valid -> {
                    var result = new LinkedHashMap<String, Object>(); result.put("active", true); result.put("client_id", token.getSpec().getClientId());
                    result.put("sub", OidcIdentityService.subject(valid.user())); result.put("scope", String.join(" ", token.getSpec().getScopes()));
                    result.put("exp", token.getSpec().getExpiresAt().getEpochSecond()); result.put("token_type", token.getSpec().getTokenType() == OidcToken.TokenType.ACCESS ? "Bearer" : "refresh_token");
                    return (Map<String, Object>) result;
                })).onErrorResume(OAuthError.class, error -> "temporarily_unavailable".equals(error.code()) ? Mono.error(error) : Mono.empty())
            .defaultIfEmpty(Map.of("active", false));
    }
    public Mono<Void> revoke(OidcClient authenticated, String raw) {
        if (raw == null || raw.isBlank() || raw.length() > 1024) {
            return Mono.empty();
        }
        return settings.enabled().then(find(raw)).filter(token -> authenticated.getMetadata().getName().equals(token.getSpec().getClientId()))
            .flatMap(token -> {
                if (token.getSpec().getTokenType() == OidcToken.TokenType.REFRESH) { return revokeFamily(token.getSpec().getFamilyName(), 8); }
                token.getSpec().setRevoked(true); return store.update(token).then();
            }).then();
    }
    private Mono<OidcToken> find(String raw) {
        return store.fetch(OidcToken.class, "token-" + OidcCrypto.digest(safeToken(raw)))
            .filter(ExtensionUtils::active).filter(value -> !value.getSpec().isRevoked());
    }
    Mono<Void> revokeFamily(String name, int attempts) {
        return Mono.defer(() -> store.fetch(OidcTokenFamily.class, name).flatMap(value -> {
            if (value.getSpec().isRevoked()) { return Mono.empty(); }
            value.getSpec().setRevoked(true); return store.update(value).then();
        })).onErrorResume(OptimisticLockingFailureException.class, error -> attempts > 1 ? revokeFamily(name, attempts - 1) : Mono.error(error));
    }
    private static String safeToken(String raw) { if (raw == null || raw.isBlank() || raw.length() > 1024) { throw OAuthError.grant(); } return raw; }
    private record ValidGrant(OidcClient client, User user) { }
}
