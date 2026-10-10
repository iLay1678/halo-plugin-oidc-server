package top.ilay.oidcserver.protocol;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.springframework.util.MultiValueMap;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.util.OidcCrypto;

public final class OidcValidation {
    public static final Set<String> SCOPES = Set.of("openid", "profile", "email", "offline_access");
    private OidcValidation() { }
    public static URI redirect(String raw) {
        try {
            var uri = URI.create(raw);
            var host = uri.getHost();
            if (!uri.isAbsolute() || host == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                || raw.contains("*") || raw.contains("\\") || uri.isOpaque() || uri.getPort() > 65535
                || !("https".equalsIgnoreCase(uri.getScheme()) || ("http".equalsIgnoreCase(uri.getScheme())
                && Set.of("localhost", "127.0.0.1", "[::1]", "::1").contains(host.toLowerCase(java.util.Locale.ROOT))))) {
                throw OAuthError.invalid("回调地址必须为 HTTPS，HTTP 仅允许精确环回地址；不能包含用户信息、片段或通配符");
            }
            return uri;
        } catch (IllegalArgumentException | NullPointerException error) { throw OAuthError.invalid("回调地址格式无效"); }
    }
    public static String one(MultiValueMap<String, String> params, String name) {
        var values = params.get(name);
        if (values != null && values.size() != 1) { throw OAuthError.invalid("参数重复：" + name); }
        var value = params.getFirst(name);
        if (value != null && value.length() > 4096) { throw OAuthError.invalid("参数过长：" + name); }
        return value;
    }
    public static String required(MultiValueMap<String, String> params, String name) {
        var value = one(params, name);
        if (value == null || value.isBlank()) { throw OAuthError.invalid("缺少参数：" + name); }
        return value;
    }
    public static List<String> scopes(String raw) {
        if (raw == null || raw.isBlank()) { throw new OAuthError("invalid_scope", "必须请求 openid 权限"); }
        var scopes = Arrays.stream(raw.split(" +")).filter(s -> !s.isBlank()).distinct().sorted().toList();
        if (!scopes.contains("openid") || !SCOPES.containsAll(scopes)) { throw new OAuthError("invalid_scope", "权限范围无效"); }
        return scopes;
    }
    public static AuthorizationRequest authorization(MultiValueMap<String, String> params, OidcClient client) {
        params.keySet().forEach(key -> one(params, key));
        var redirect = required(params, "redirect_uri");
        if (!client.getSpec().getRedirectUris().contains(redirect)) { throw OAuthError.invalid("回调地址未登记"); }
        redirect(redirect);
        if (!"code".equals(required(params, "response_type"))) { throw new OAuthError("unsupported_response_type", "仅支持授权码流程"); }
        var mode = one(params, "response_mode");
        if (mode != null && !"query".equals(mode)) { throw OAuthError.invalid("仅支持 query 响应模式"); }
        for (var unsupported : List.of("max_age", "claims", "request", "request_uri", "id_token_hint", "login_hint", "acr_values")) {
            if (params.containsKey(unsupported)) { throw OAuthError.invalid("暂不支持参数：" + unsupported); }
        }
        var scopes = scopes(required(params, "scope"));
        if (!client.getSpec().getScopes().containsAll(scopes)) { throw new OAuthError("invalid_scope", "应用未开放请求的权限"); }
        var challenge = one(params, "code_challenge");
        var challengeMethod = one(params, "code_challenge_method");
        if ((challenge == null && challengeMethod != null) || (challenge != null && challengeMethod == null)) {
            throw OAuthError.invalid("code_challenge 与 code_challenge_method 必须同时提供");
        }
        if (challenge != null && (!"S256".equals(challengeMethod) || !challenge.matches("[A-Za-z0-9_-]{43}"))) {
            throw OAuthError.invalid("必须使用 PKCE S256");
        }
        if (client.getSpec().getClientType() == OidcClient.ClientType.PUBLIC && challenge == null) {
            throw OAuthError.invalid("公开客户端必须使用 PKCE S256");
        }
        var prompt = one(params, "prompt");
        if (prompt != null && !Set.of("none", "consent").contains(prompt)) { throw OAuthError.invalid("仅支持 prompt=none 或 consent，且不能组合"); }
        var nonce = one(params, "nonce");
        if (nonce != null && (nonce.isBlank() || nonce.length() > 512)) { throw OAuthError.invalid("nonce 无效"); }
        return new AuthorizationRequest(client.getMetadata().getName(), redirect, scopes, one(params, "state"), nonce, challenge, prompt);
    }
    public record AuthorizationRequest(String clientId, String redirectUri, List<String> scopes, String state, String nonce, String challenge, String prompt) implements java.io.Serializable { }
    public static void verifier(String verifier, String challenge) {
        if (challenge == null) {
            if (verifier != null) { throw OAuthError.grant(); }
            return;
        }
        if (verifier == null || !verifier.matches("[A-Za-z0-9._~-]{43,128}") || !OidcCrypto.equal(OidcCrypto.challenge(verifier), challenge)) { throw OAuthError.grant(); }
    }
}
