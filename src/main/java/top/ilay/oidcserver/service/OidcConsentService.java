package top.ilay.oidcserver.service;

import java.time.Clock;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.User;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.PageRequestImpl;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.index.query.Queries;
import run.halo.app.extension.router.selector.FieldSelector;
import top.ilay.oidcserver.dto.OidcConsentPage;
import top.ilay.oidcserver.dto.OidcConsentResponse;
import top.ilay.oidcserver.extension.GrantBinding;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.util.ExtensionUtils;
import top.ilay.oidcserver.util.OidcCrypto;

@Service
@RequiredArgsConstructor
public class OidcConsentService {
    private final ReactiveExtensionClient store;
    private final OidcClientService clients;
    private final OidcIdentityService identities;
    private final Clock clock;
    static String name(String subject, String clientId) { return "consent-" + OidcCrypto.digest(subject + "\0" + clientId); }
    private Mono<OidcConsent> find(User user, OidcClient client) {
        var clientId = client.getMetadata().getName();
        // 旧版本使用用户名命名；只允许原账户复用，不覆盖同名旧账户的记录。
        return store.fetch(OidcConsent.class, name(OidcIdentityService.subject(user), clientId))
            .switchIfEmpty(Mono.defer(() -> store.fetch(OidcConsent.class, name(user.getMetadata().getName(), clientId))))
            .filter(ExtensionUtils::active).filter(value -> ownedBy(value, user));
    }
    private static boolean ownedBy(OidcConsent value, User user) {
        return value.getSpec() != null && user.getMetadata().getName().equals(value.getSpec().getUsername())
            && OidcIdentityService.subject(user).equals(value.getSpec().getSubject());
    }
    public Mono<OidcConsent> reusable(User expected, OidcClient client, List<String> scopes) {
        return identities.user(expected).flatMap(user -> find(user, client)
            .filter(value -> !value.getSpec().isRevoked()
                && value.getSpec().getClientVersion() == client.getSpec().getSecurityVersion() && value.getSpec().getScopes().containsAll(scopes)));
    }
    public Mono<OidcConsent> grant(User expected, OidcClient client, List<String> scopes) {
        return identities.protect(expected).flatMap(user -> find(user, client).flatMap(existing -> {
            fill(existing, user.getMetadata().getName(), client, scopes);
            return store.update(existing);
        }).switchIfEmpty(Mono.defer(() -> {
            var value = OidcCrypto.named(new OidcConsent(), name(OidcIdentityService.subject(user), client.getMetadata().getName()));
            value.setSpec(new OidcConsent.Spec());
            fill(value, user.getMetadata().getName(), client, scopes);
            value.getSpec().setSubject(OidcIdentityService.subject(user));
            return store.create(value);
        })).flatMap(saved -> identities.user(expected).thenReturn(saved)
            .onErrorResume(OAuthError.class, error -> store.delete(saved).then(Mono.error(error)))));
    }
    private void fill(OidcConsent value, String username, OidcClient client, List<String> scopes) {
        var spec = value.getSpec(); spec.setUsername(username); spec.setClientId(client.getMetadata().getName());
        spec.setScopes(List.copyOf(scopes)); spec.setClientVersion(client.getSpec().getSecurityVersion());
        spec.setAuthorizationVersion(OidcCrypto.random()); spec.setRevoked(false); spec.setGrantedAt(clock.instant());
    }
    public Mono<OidcConsent> validate(GrantBinding binding) {
        return store.fetch(OidcConsent.class, binding.getConsentName()).filter(ExtensionUtils::active)
            .filter(value -> !value.getSpec().isRevoked() && value.getSpec().getUsername().equals(binding.getUsername())
                && value.getSpec().getClientId().equals(binding.getClientId())
                && java.util.Objects.equals(value.getSpec().getSubject(), binding.getSubject())
                && value.getSpec().getAuthorizationVersion().equals(binding.getConsentVersion())
                && value.getSpec().getScopes().containsAll(binding.getScopes()))
            .switchIfEmpty(Mono.error(OAuthError.grant()));
    }
    public Mono<OidcConsentResponse> revoke(String name, User user) { return revoke(name, user, 4); }
    private Mono<OidcConsentResponse> revoke(String name, User user, int attempts) {
        return Mono.defer(() -> identities.user(user).then(store.fetch(OidcConsent.class, name))
            .filter(ExtensionUtils::active).filter(value -> ownedBy(value, user))
            .switchIfEmpty(Mono.error(new OAuthError("access_denied", "授权记录不存在", org.springframework.http.HttpStatus.NOT_FOUND)))
            .flatMap(value -> {
                if (value.getSpec().isRevoked()) { return response(value); }
                value.getSpec().setRevoked(true); value.getSpec().setAuthorizationVersion(OidcCrypto.random());
                return store.update(value).flatMap(this::response);
            })).onErrorResume(OptimisticLockingFailureException.class, error -> attempts > 1 ? revoke(name, user, attempts - 1) : Mono.error(error));
    }
    public Mono<OidcConsentPage> list(User user, int page, int size) {
        OidcClientService.page(page, size);
        var conditions = Queries.and(Queries.equal("spec.username", user.getMetadata().getName()),
            Queries.equal("spec.subject", OidcIdentityService.subject(user)),
            Queries.equal("spec.revoked", false), Queries.isNull("metadata.deletionTimestamp"));
        return identities.user(user).then(store.listBy(OidcConsent.class, new ListOptions().setFieldSelector(FieldSelector.of(conditions)),
            PageRequestImpl.of(page, size, Sort.by(Sort.Direction.DESC, "spec.grantedAt")))).flatMap(result ->
                reactor.core.publisher.Flux.fromIterable(result.getItems()).concatMap(this::response).collectList()
                    .map(items -> new OidcConsentPage(result.getPage(), result.getSize(), result.getTotal(), items)));
    }
    private Mono<OidcConsentResponse> response(OidcConsent value) {
        return clients.get(value.getSpec().getClientId()).map(client -> new OidcConsentResponse(value.getMetadata().getName(),
            value.getSpec().getClientId(), client.getSpec().getDisplayName(), value.getSpec().getScopes(), value.getSpec().getGrantedAt(), value.getSpec().isRevoked()))
            .onErrorResume(OAuthError.class, error -> Mono.just(new OidcConsentResponse(value.getMetadata().getName(), value.getSpec().getClientId(),
                "已删除应用", value.getSpec().getScopes(), value.getSpec().getGrantedAt(), value.getSpec().isRevoked())));
    }
}
