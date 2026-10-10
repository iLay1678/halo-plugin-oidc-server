package top.ilay.oidcserver.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import reactor.core.publisher.Mono;
import top.ilay.oidcserver.support.OidcTestFixture;
import top.ilay.oidcserver.util.OidcCrypto;

class OidcAuthorizationControllerTest extends OidcTestFixture {
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
}
