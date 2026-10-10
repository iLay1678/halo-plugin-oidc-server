package top.ilay.oidcserver;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.PageRequestImpl;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.index.query.Queries;
import run.halo.app.extension.router.selector.FieldSelector;

@Service
@RequiredArgsConstructor
public class OidcConsentService {
    private final ReactiveExtensionClient store;
    private final OidcClientService clients;
    private final OidcIdentityService identities;
    private final Clock clock;
    static String name(String username, String clientId) { return "consent-" + OidcCrypto.digest(username + "\0" + clientId); }
    public Mono<OidcConsent> reusable(String username, OidcClient client, List<String> scopes) {
        return identities.user(username).flatMap(user -> store.fetch(OidcConsent.class, name(username, client.getMetadata().getName()))
            .filter(OidcIdentityService::active).filter(value -> !value.getSpec().isRevoked()
                && OidcIdentityService.subject(user).equals(value.getSpec().getSubject())
                && value.getSpec().getClientVersion() == client.getSpec().getSecurityVersion() && value.getSpec().getScopes().containsAll(scopes)));
    }
    public Mono<OidcConsent> grant(String username, OidcClient client, List<String> scopes) {
        var name = name(username, client.getMetadata().getName());
        return identities.user(username).flatMap(user -> store.fetch(OidcConsent.class, name).flatMap(existing -> {
            fill(existing, username, client, scopes);
            existing.getSpec().setSubject(OidcIdentityService.subject(user));
            return store.update(existing);
        }).switchIfEmpty(Mono.defer(() -> {
            var value = OidcCrypto.named(new OidcConsent(), name); value.setSpec(new OidcConsent.Spec());
            fill(value, username, client, scopes); value.getSpec().setSubject(OidcIdentityService.subject(user)); return store.create(value);
        })));
    }
    private void fill(OidcConsent value, String username, OidcClient client, List<String> scopes) {
        var spec = value.getSpec(); spec.setUsername(username); spec.setClientId(client.getMetadata().getName());
        spec.setScopes(List.copyOf(scopes)); spec.setClientVersion(client.getSpec().getSecurityVersion());
        spec.setAuthorizationVersion(OidcCrypto.random()); spec.setRevoked(false); spec.setGrantedAt(clock.instant());
    }
    public Mono<OidcConsent> validate(GrantBinding binding) {
        return store.fetch(OidcConsent.class, binding.getConsentName()).filter(OidcIdentityService::active)
            .filter(value -> !value.getSpec().isRevoked() && value.getSpec().getUsername().equals(binding.getUsername())
                && value.getSpec().getClientId().equals(binding.getClientId())
                && java.util.Objects.equals(value.getSpec().getSubject(), binding.getSubject())
                && value.getSpec().getAuthorizationVersion().equals(binding.getConsentVersion())
                && value.getSpec().getScopes().containsAll(binding.getScopes()))
            .switchIfEmpty(Mono.error(OAuthError.grant()));
    }
    public Mono<OidcConsentResponse> revoke(String name, String username) { return revoke(name, username, 4); }
    private Mono<OidcConsentResponse> revoke(String name, String username, int attempts) {
        return Mono.defer(() -> store.fetch(OidcConsent.class, name)
            .filter(value -> value.getSpec().getUsername().equals(username))
            .switchIfEmpty(Mono.error(new OAuthError("access_denied", "授权记录不存在", org.springframework.http.HttpStatus.NOT_FOUND)))
            .flatMap(value -> {
                if (value.getSpec().isRevoked()) { return response(value); }
                value.getSpec().setRevoked(true); value.getSpec().setAuthorizationVersion(OidcCrypto.random());
                return store.update(value).flatMap(this::response);
            })).onErrorResume(OptimisticLockingFailureException.class, error -> attempts > 1 ? revoke(name, username, attempts - 1) : Mono.error(error));
    }
    public Mono<OidcConsentPage> list(String username, int page, int size) {
        OidcClientService.page(page, size);
        var conditions = Queries.and(Queries.equal("spec.username", username), Queries.equal("spec.revoked", false));
        return store.listBy(OidcConsent.class, new ListOptions().setFieldSelector(FieldSelector.of(conditions)),
            PageRequestImpl.of(page, size, Sort.by(Sort.Direction.DESC, "spec.grantedAt"))).flatMap(result ->
                reactor.core.publisher.Flux.fromIterable(result.getItems()).concatMap(this::response).collectList()
                    .map(items -> new OidcConsentPage(result.getPage(), result.getSize(), result.getTotal(), items)));
    }
    private Mono<OidcConsentResponse> response(OidcConsent value) {
        return clients.get(value.getSpec().getClientId()).map(client -> new OidcConsentResponse(value.getMetadata().getName(),
            value.getSpec().getClientId(), client.getSpec().getDisplayName(), value.getSpec().getScopes(), value.getSpec().getGrantedAt(), value.getSpec().isRevoked()))
            .onErrorResume(OAuthError.class, error -> Mono.just(new OidcConsentResponse(value.getMetadata().getName(), value.getSpec().getClientId(),
                "已删除应用", value.getSpec().getScopes(), value.getSpec().getGrantedAt(), value.getSpec().isRevoked())));
    }
    @io.swagger.v3.oas.annotations.media.Schema(name = "OidcConsentResponse")
    public record OidcConsentResponse(String name, String clientId, String displayName, List<String> scopes, Instant grantedAt, boolean revoked) { }
    @io.swagger.v3.oas.annotations.media.Schema(name = "OidcConsentPage")
    public record OidcConsentPage(int page, int size, long total, List<OidcConsentResponse> items) { }
}
