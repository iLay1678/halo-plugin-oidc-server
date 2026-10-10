package top.ilay.oidcserver;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.pf4j.Extension;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.security.BeforeSecurityWebFilter;

/** 仅接管协议入口，不向 Halo 安全上下文注入 OIDC 身份。 */
@Component
@Extension
@RequiredArgsConstructor
public class OidcProtocolFilter implements BeforeSecurityWebFilter, Ordered {
    private static final Set<String> PATHS = Set.of("/oidc/token", "/oidc/userinfo", "/oidc/revoke", "/oidc/introspect");
    private final OidcClientService clients;
    private final OidcTokenService tokens;
    private final tools.jackson.databind.ObjectMapper mapper = new tools.jackson.databind.ObjectMapper();
    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 100; }
    @Override public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (!PATHS.contains(path)) { return chain.filter(exchange); }
        return Mono.defer(() -> {
            var method = exchange.getRequest().getMethod();
            if (path.equals("/oidc/userinfo")) {
                if (method != HttpMethod.GET && method != HttpMethod.POST) { return json(exchange, HttpStatus.METHOD_NOT_ALLOWED, Map.of("error", "invalid_request")); }
                var header = header(exchange);
                if (!hasScheme(header, "Bearer") || header.substring(7).isBlank() || header.substring(7).contains(" ")) { throw OAuthError.token(); }
                if (exchange.getRequest().getQueryParams().containsKey("access_token")) { throw OAuthError.invalid("仅允许 Authorization Bearer 传递访问令牌"); }
                return tokens.userinfo(header.substring(7)).flatMap(body -> json(exchange, HttpStatus.OK, body));
            }
            if (method != HttpMethod.POST) { return json(exchange, HttpStatus.METHOD_NOT_ALLOWED, Map.of("error", "invalid_request")); }
            var media = exchange.getRequest().getHeaders().getContentType();
            if (media == null || !MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(media)) { throw OAuthError.invalid("请求必须使用 application/x-www-form-urlencoded"); }
            return exchange.getFormData().flatMap(form -> {
                form.keySet().forEach(key -> {
                    // RFC 7009 要求 token 无论空白、未知或超长都按成功撤销响应处理；其余参数仍严格校验。
                    if (!(path.equals("/oidc/revoke") && key.equals("token"))) { OidcValidation.one(form, key); }
                });
                return authenticate(exchange, form).flatMap(client -> switch (path) {
                    case "/oidc/token" -> token(form, client).flatMap(body -> json(exchange, HttpStatus.OK, body));
                    case "/oidc/introspect" -> tokens.introspect(client, OidcValidation.required(form, "token")).flatMap(body -> json(exchange, HttpStatus.OK, body));
                    case "/oidc/revoke" -> revoke(form, client).then(json(exchange, HttpStatus.OK, Map.of()));
                    default -> Mono.error(OAuthError.invalid("未知协议入口"));
                });
            });
        }).onErrorResume(OAuthError.class, error -> {
            if (error.status() == HttpStatus.UNAUTHORIZED) {
                exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
                    error.code().equals("invalid_client") ? "Basic realm=\"oidc\"" : "Bearer error=\"invalid_token\"");
            }
            return json(exchange, error.status(), error.body());
        }).onErrorResume(error -> json(exchange, HttpStatus.SERVICE_UNAVAILABLE,
            Map.of("error", "temporarily_unavailable", "error_description", "OIDC 服务暂时不可用")));
    }
    private Mono<Map<String, Object>> token(MultiValueMap<String, String> form, OidcClient client) {
        return switch (OidcValidation.required(form, "grant_type")) {
            case "authorization_code" -> tokens.exchange(client, OidcValidation.required(form, "code"),
                OidcValidation.required(form, "redirect_uri"), OidcValidation.one(form, "code_verifier"));
            case "refresh_token" -> tokens.refresh(client, OidcValidation.required(form, "refresh_token"), OidcValidation.one(form, "scope"));
            default -> Mono.error(new OAuthError("unsupported_grant_type", "仅支持授权码与刷新令牌"));
        };
    }
    /** RFC 7009：已通过客户端认证后，令牌不存在、过期、过长或不属于该客户端均返回 200 空响应。 */
    private Mono<Void> revoke(MultiValueMap<String, String> form, OidcClient client) {
        var values = form.get("token");
        if (values == null || values.size() != 1) {
            return Mono.empty();
        }
        var raw = values.getFirst();
        if (raw == null || raw.isBlank() || raw.length() > 1024) {
            return Mono.empty();
        }
        return tokens.revoke(client, raw).onErrorResume(OAuthError.class, error ->
            "invalid_grant".equals(error.code()) || "invalid_token".equals(error.code())
                ? Mono.empty() : Mono.error(error));
    }
    private Mono<OidcClient> authenticate(ServerWebExchange exchange, MultiValueMap<String, String> form) {
        var authorization = header(exchange);
        var id = OidcValidation.one(form, "client_id"); var secret = OidcValidation.one(form, "client_secret");
        if (authorization != null) {
            if (!hasScheme(authorization, "Basic") || id != null || secret != null) { return Mono.error(OAuthError.client()); }
            try {
                var decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
                var colon = decoded.indexOf(':'); if (colon < 1) { return Mono.error(OAuthError.client()); }
                id = URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8);
                secret = URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException error) { return Mono.error(OAuthError.client()); }
        }
        return clients.authenticate(id, secret, authorization != null || form.containsKey("client_secret"));
    }
    private static String header(ServerWebExchange exchange) {
        var values = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (values != null && values.size() != 1) { throw OAuthError.invalid("Authorization 头不能重复"); }
        return exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    }
    static boolean hasScheme(String value, String scheme) {
        return value != null && value.length() > scheme.length() + 1
            && value.regionMatches(true, 0, scheme, 0, scheme.length())
            && Character.isWhitespace(value.charAt(scheme.length()));
    }
    private Mono<Void> json(ServerWebExchange exchange, HttpStatus status, Object body) {
        var response = exchange.getResponse(); response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().setCacheControl("no-store"); response.getHeaders().setPragma("no-cache");
        return response.writeWith(Mono.fromSupplier(() -> response.bufferFactory().wrap(mapper.writeValueAsBytes(body))));
    }
}
