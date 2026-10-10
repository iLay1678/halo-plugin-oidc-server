package top.ilay.oidcserver.protocol;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import top.ilay.oidcserver.support.OidcTestFixture;

class OidcProtocolFilterTest extends OidcTestFixture {
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
}
