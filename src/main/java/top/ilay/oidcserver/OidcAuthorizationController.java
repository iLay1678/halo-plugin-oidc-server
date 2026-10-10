package top.ilay.oidcserver;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import top.ilay.oidcserver.OidcValidation.AuthorizationRequest;

@Controller
@RequiredArgsConstructor
public class OidcAuthorizationController {
    private static final String PENDING = "oidc-server.pending";
    private final OidcSettings settings;
    private final OidcClientService clients;
    private final OidcConsentService consents;
    private final OidcIdentityService identities;
    private final OidcTokenService tokens;
    private final OidcSigningService signing;
    private final Clock clock;

    @GetMapping({"/oidc/.well-known/openid-configuration", "/.well-known/openid-configuration"})
    @ResponseBody
    public Mono<ResponseEntity<?>> discovery() {
        return Mono.<ResponseEntity<?>>fromSupplier(() -> {
            var issuer = settings.issuer(); var result = new LinkedHashMap<String, Object>();
            result.put("issuer", issuer); result.put("authorization_endpoint", issuer + "/authorize"); result.put("token_endpoint", issuer + "/token");
            result.put("userinfo_endpoint", issuer + "/userinfo"); result.put("jwks_uri", issuer + "/jwks");
            result.put("revocation_endpoint", issuer + "/revoke"); result.put("introspection_endpoint", issuer + "/introspect");
            result.put("response_types_supported", List.of("code")); result.put("response_modes_supported", List.of("query"));
            result.put("grant_types_supported", List.of("authorization_code", "refresh_token")); result.put("subject_types_supported", List.of("public"));
            result.put("id_token_signing_alg_values_supported", List.of("RS256")); result.put("scopes_supported", List.of("openid", "profile", "email", "offline_access"));
            result.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none"));
            result.put("introspection_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"));
            result.put("revocation_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none"));
            result.put("code_challenge_methods_supported", List.of("S256"));
            result.put("claims_supported", List.of("iss", "sub", "aud", "iat", "exp", "nonce", "at_hash", "name", "preferred_username", "picture", "email", "email_verified"));
            return (ResponseEntity<?>) ResponseEntity.ok(result);
        }).onErrorResume(error -> Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "temporarily_unavailable"))));
    }
    @GetMapping("/oidc/jwks") @ResponseBody public Mono<Map<String, Object>> jwks() { return signing.jwks(); }

    @GetMapping("/oidc/authorize")
    public Mono<ResponseEntity<?>> authorize(ServerWebExchange exchange) {
        return settings.enabled().then(Mono.defer(() -> {
            var params = exchange.getRequest().getQueryParams();
            return clients.enabled(OidcValidation.required(params, "client_id")).flatMap(client -> {
                var request = OidcValidation.authorization(params, client);
                return identities.current().flatMap(user -> identities.allowed(client, user.getMetadata().getName()).thenReturn(user))
                    .flatMap(user -> {
                        var username = user.getMetadata().getName();
                        var reusable = "consent".equals(request.prompt()) ? Mono.<OidcConsent>empty() : consents.reusable(username, client, request.scopes());
                        return reusable.flatMap(consent -> redirectCode(request, client, consent))
                            .switchIfEmpty(Mono.defer(() -> {
                                if ("none".equals(request.prompt())) { return Mono.just(callback(request, "error", "consent_required")); }
                                return consentPage(exchange, request, client, username);
                            }));
                    }).onErrorResume(OAuthError.class, error -> {
                        if ("login_required".equals(error.code())) {
                            if ("none".equals(request.prompt())) { return Mono.just(callback(request, "error", "login_required")); }
                            var original = exchange.getRequest().getURI().getRawPath();
                            var rawQuery = exchange.getRequest().getURI().getRawQuery();
                            if (rawQuery != null && !rawQuery.isEmpty()) { original += "?" + rawQuery; }
                            return Mono.just(redirect(loginTarget(original)));
                        }
                        return Mono.just(callback(request, "error", error.code()));
                    });
            });
        })).onErrorResume(error -> Mono.just(localError(error)));
    }
    @PostMapping("/oidc/authorize")
    public Mono<ResponseEntity<?>> decide(ServerWebExchange exchange) {
        return settings.enabled().then(exchange.getFormData()).flatMap(form -> exchange.getSession().flatMap(session -> {
            var pending = (Pending) session.getAttributes().get(PENDING);
            if (pending == null || !pending.expiresAt().isAfter(clock.instant())
                || !OidcCrypto.equal(pending.id(), OidcValidation.required(form, "request_id"))) { return Mono.error(OAuthError.invalid("授权确认已过期，请重新开始登录")); }
            var decision = OidcValidation.required(form, "decision");
            if (!List.of("allow", "deny").contains(decision)) { return Mono.error(OAuthError.invalid("授权决定无效")); }
            return identities.current().filter(user -> user.getMetadata().getName().equals(pending.username()))
                .switchIfEmpty(Mono.error(new OAuthError("access_denied", "授权用户已发生变化")))
                .flatMap(user -> clients.enabled(pending.request().clientId()).flatMap(client -> {
                    if (client.getSpec().getSecurityVersion() != pending.clientVersion()
                        || !client.getSpec().getRedirectUris().contains(pending.request().redirectUri())
                        || !client.getSpec().getScopes().containsAll(pending.request().scopes())) { return Mono.error(OAuthError.invalid("应用配置已变化，请重新开始授权")); }
                    return identities.allowed(client, user.getMetadata().getName()).flatMap(allowed -> {
                        session.getAttributes().remove(PENDING);
                        if ("deny".equals(decision)) { return Mono.just(callback(pending.request(), "error", "access_denied")); }
                        // 包含 offline_access 的确认页明确显示保持授权，只有显式同意才签发刷新令牌。
                        return consents.grant(user.getMetadata().getName(), client, pending.request().scopes()).flatMap(consent -> redirectCode(pending.request(), client, consent));
                    });
                }));
        })).onErrorResume(error -> Mono.just(localError(error)));
    }
    private Mono<ResponseEntity<?>> redirectCode(AuthorizationRequest request, OidcClient client, OidcConsent consent) {
        return tokens.authorize(request, client, consent).map(code -> callback(request, "code", code));
    }
    private Mono<ResponseEntity<?>> consentPage(ServerWebExchange exchange, AuthorizationRequest request, OidcClient client, String username) {
        Mono<CsrfToken> csrf = exchange.getAttribute(CsrfToken.class.getName());
        if (csrf == null) { return Mono.error(new IllegalStateException("Halo CSRF 防护未就绪")); }
        return csrf.flatMap(token -> exchange.getSession().map(session -> {
            var pending = new Pending(OidcCrypto.random(), username, client.getSpec().getSecurityVersion(), request, clock.instant().plusSeconds(600));
            session.getAttributes().put(PENDING, pending);
            var html = OidcConsentPage.render(request, client, username, token, pending.id());
            return (ResponseEntity<?>) ResponseEntity.ok().headers(consentHeaders(request)).contentType(MediaType.TEXT_HTML).body(html);
        }));
    }
    static ResponseEntity<?> callback(AuthorizationRequest request, String key, String value) {
        var target = request.redirectUri() + (request.redirectUri().contains("?") ? "&" : "?")
            + key + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
        if (request.state() != null) { target += "&state=" + URLEncoder.encode(request.state(), StandardCharsets.UTF_8); }
        return redirect(target);
    }
    private static ResponseEntity<?> redirect(String target) { return ResponseEntity.status(HttpStatus.FOUND).headers(noCache()).location(URI.create(target)).build(); }
    static String loginTarget(String original) {
        // query-param 编码会保留 +，Halo 登录页会将其解码为空格，必须对整个嵌套 URL 做表单编码。
        return "/login?redirect_uri=" + URLEncoder.encode(original, StandardCharsets.UTF_8);
    }
    static HttpHeaders consentHeaders(AuthorizationRequest request) {
        var headers = noCache();
        var callback = OidcValidation.redirect(request.redirectUri());
        // Chromium 会检查表单提交后的重定向目标，仅允许已校验的应用回调来源。
        headers.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' "
            + callback.getScheme() + "://" + callback.getRawAuthority() + "; frame-ancestors 'none'; base-uri 'none'");
        return headers;
    }
    private static ResponseEntity<?> localError(Throwable error) {
        var oauth = error instanceof OAuthError known ? known : new OAuthError("temporarily_unavailable", "OIDC 服务暂时不可用", HttpStatus.SERVICE_UNAVAILABLE);
        return ResponseEntity.status(oauth.status()).headers(noCache()).contentType(MediaType.APPLICATION_JSON).body(oauth.body());
    }
    static HttpHeaders noCache() {
        var headers = new HttpHeaders(); headers.setCacheControl("no-store"); headers.setPragma("no-cache");
        headers.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
        headers.set("Referrer-Policy", "no-referrer"); return headers;
    }
    private record Pending(String id, String username, long clientVersion, AuthorizationRequest request, Instant expiresAt) implements java.io.Serializable { }
}
