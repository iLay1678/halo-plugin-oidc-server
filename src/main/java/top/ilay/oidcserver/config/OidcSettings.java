package top.ilay.oidcserver.config;

import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import run.halo.app.infra.ExternalUrlSupplier;
import run.halo.app.plugin.ReactiveSettingFetcher;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.protocol.OidcValidation;

@Service
@RequiredArgsConstructor
public class OidcSettings {
    private final ReactiveSettingFetcher settings;
    private final ExternalUrlSupplier externalUrl;
    public record Lifetimes(Integer codeSeconds, Integer accessSeconds, Integer idSeconds, Integer refreshDays) { }
    public record Security(Boolean enabled) { }
    public Mono<Void> enabled() {
        return settings.fetch("security", Security.class).filter(value -> Boolean.TRUE.equals(value.enabled()))
            .switchIfEmpty(Mono.error(new OAuthError("temporarily_unavailable", "OIDC 服务尚未启用", org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE)))
            .then(Mono.fromRunnable(this::issuer));
    }
    public Mono<Lifetimes> lifetimes() {
        return settings.fetch("protocol", Lifetimes.class).map(value -> new Lifetimes(
                bounded(value.codeSeconds(), 120, 30, 300), bounded(value.accessSeconds(), 900, 60, 3600),
                bounded(value.idSeconds(), 900, 60, 3600), bounded(value.refreshDays(), 30, 1, 90)))
            .defaultIfEmpty(new Lifetimes(120, 900, 900, 30));
    }
    private static int bounded(Integer value, int fallback, int min, int max) {
        if (value == null) { return fallback; }
        if (value < min || value > max) { throw new IllegalStateException("OIDC 有效期配置超出允许范围"); }
        return value;
    }
    public String issuer() {
        var configured = externalUrl.getRaw();
        if (configured == null) { throw new IllegalStateException("请先配置 Halo 固定外部访问地址"); }
        var raw = configured.toString();
        OidcValidation.redirect(raw);
        var uri = URI.create(raw);
        if (uri.getQuery() != null) { throw new IllegalStateException("Halo 外部访问地址不能包含查询参数"); }
        return raw.replaceAll("/+$", "") + "/oidc";
    }
}
