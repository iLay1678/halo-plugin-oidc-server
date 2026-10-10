package top.ilay.oidcserver;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.Role;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.PageRequestImpl;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.Secret;
import run.halo.app.extension.index.query.Queries;
import run.halo.app.extension.router.selector.FieldSelector;

@Service
@RequiredArgsConstructor
public class OidcClientService {
    private final ReactiveExtensionClient store;
    public Mono<OidcClient> get(String id) {
        if (id == null || !id.matches("oc-[a-f0-9]{32}")) { return Mono.error(OAuthError.client()); }
        return store.fetch(OidcClient.class, id).filter(OidcIdentityService::active)
            .filter(client -> client.getSpec() != null && !client.getSpec().isDeleted())
            .switchIfEmpty(Mono.error(OAuthError.client()));
    }
    public Mono<OidcClient> enabled(String id) { return get(id).filter(value -> value.getSpec().isEnabled()).switchIfEmpty(Mono.error(OAuthError.client())); }
    public Mono<OidcClientPage> list(int page, int size, String keyword) {
        page(page, size);
        var condition = Queries.equal("spec.deleted", false);
        if (keyword != null && !keyword.isBlank()) { condition = Queries.and(condition, Queries.contains("spec.displayName", keyword.trim())); }
        return store.listBy(OidcClient.class, new ListOptions().setFieldSelector(FieldSelector.of(condition)),
            PageRequestImpl.of(page, size, Sort.by(Sort.Direction.DESC, "metadata.creationTimestamp")))
            .map(result -> new OidcClientPage(result.getPage(), result.getSize(), result.getTotal(),
                result.getItems().stream().map(value -> OidcClientResponse.of(value, null)).toList()));
    }
    public Mono<OidcClientResponse> create(OidcClientRequest request) {
        return validate(request).then(Mono.defer(() -> {
            var id = "oc-" + OidcCrypto.digest(OidcCrypto.random()).substring(0, 32);
            var value = OidcCrypto.named(new OidcClient(), id);
            var spec = new OidcClient.Spec(); request.apply(spec); spec.setSecurityVersion(1); value.setSpec(spec);
            if (spec.getClientType() == OidcClient.ClientType.PUBLIC) { return store.create(value).map(saved -> OidcClientResponse.of(saved, null)); }
            return newSecret(id).flatMap(secret -> {
                spec.setSecretRef(secret.name());
                return store.create(value).map(saved -> OidcClientResponse.of(saved, secret.raw()))
                    .onErrorResume(error -> compensate(secret).then(Mono.error(error)));
            });
        }));
    }
    public Mono<OidcClientResponse> update(String name, OidcClientRequest request) {
        return validate(request).then(get(name)).flatMap(value -> {
            if (value.getSpec().getClientType() != request.clientType()) { return Mono.error(OAuthError.invalid("客户端类型创建后不可修改")); }
            request.apply(value.getSpec()); value.getSpec().setSecurityVersion(value.getSpec().getSecurityVersion() + 1);
            return store.update(value).map(saved -> OidcClientResponse.of(saved, null));
        });
    }
    public Mono<OidcClientResponse> state(String name, boolean enabled, boolean deleted) {
        return get(name).flatMap(value -> {
            value.getSpec().setEnabled(enabled); value.getSpec().setDeleted(deleted);
            value.getSpec().setSecurityVersion(value.getSpec().getSecurityVersion() + 1);
            return store.update(value).map(saved -> OidcClientResponse.of(saved, null));
        });
    }
    public Mono<OidcClientResponse> reset(String name) {
        return get(name).flatMap(value -> {
            if (value.getSpec().getClientType() != OidcClient.ClientType.CONFIDENTIAL) { return Mono.error(OAuthError.invalid("公开客户端没有密钥")); }
            // 密钥采用新引用；客户端 CAS 失败时旧客户端仍使用旧摘要。
            return newSecret(name).flatMap(secret -> {
                value.getSpec().setSecretRef(secret.name()); value.getSpec().setSecurityVersion(value.getSpec().getSecurityVersion() + 1);
                return store.update(value).map(saved -> OidcClientResponse.of(saved, secret.raw()))
                    .onErrorResume(error -> compensate(secret).then(Mono.error(error)));
            });
        });
    }
    public Mono<OidcClient> authenticate(String id, String secret, boolean suppliedSecret) {
        return enabled(id).flatMap(value -> {
            if (value.getSpec().getClientType() == OidcClient.ClientType.PUBLIC) { return suppliedSecret ? Mono.error(OAuthError.client()) : Mono.just(value); }
            if (!suppliedSecret || secret == null || secret.length() > 512 || value.getSpec().getSecretRef() == null) { return Mono.error(OAuthError.client()); }
            return store.fetch(Secret.class, value.getSpec().getSecretRef()).filter(OidcIdentityService::active)
                .filter(stored -> stored.getData() != null && stored.getData().containsKey("digest"))
                .filter(stored -> java.security.MessageDigest.isEqual(stored.getData().get("digest"), OidcCrypto.hash(secret)))
                .map(ignored -> value).switchIfEmpty(Mono.error(OAuthError.client()));
        });
    }
    private Mono<SecretValue> newSecret(String id) {
        return Mono.defer(() -> {
            var raw = OidcCrypto.random(); var name = "oidc-secret-" + OidcCrypto.digest(id + raw).substring(0, 40);
            var value = OidcCrypto.named(new Secret(), name); value.setType(Secret.SECRET_TYPE_OPAQUE);
            value.setData(Map.of("digest", OidcCrypto.hash(raw)));
            return store.create(value).map(saved -> new SecretValue(saved, raw));
        });
    }
    private Mono<Void> compensate(SecretValue secret) {
        return store.delete(secret.resource()).onErrorResume(ignored -> Mono.empty()).then();
    }
    private Mono<Void> validate(OidcClientRequest request) {
        return Mono.defer(() -> {
            request.validate();
            if (request.accessPolicy() == OidcClient.AccessPolicy.ALL) { return Mono.empty(); }
            return Flux.fromIterable(request.roles()).concatMap(name -> store.fetch(Role.class, name)
                .filter(OidcIdentityService::selectableRole).switchIfEmpty(Mono.error(OAuthError.invalid("角色不存在或不可选择")))).then();
        });
    }
    public Mono<RoleCandidateList> roles(String keyword) {
        return store.list(Role.class, OidcIdentityService::selectableRole, java.util.Comparator.comparing(role -> role.getMetadata().getName()))
            .filter(role -> keyword == null || keyword.isBlank() || role.getMetadata().getName().contains(keyword) || display(role).contains(keyword))
            .take(100).map(role -> new RoleCandidate(role.getMetadata().getName(), display(role))).collectList().map(RoleCandidateList::new);
    }
    private static String display(Role role) {
        var annotations = role.getMetadata().getAnnotations();
        return annotations == null ? role.getMetadata().getName() : annotations.getOrDefault("rbac.authorization.halo.run/display-name", role.getMetadata().getName());
    }
    static void page(int page, int size) { if (page < 1 || size < 1 || size > 100) { throw OAuthError.invalid("页码必须大于 0，每页数量为 1–100"); } }
    private record SecretValue(Secret resource, String raw) {
        private String name() { return resource.getMetadata().getName(); }
    }
    @io.swagger.v3.oas.annotations.media.Schema(name = "OidcClientPage")
    public record OidcClientPage(int page, int size, long total, List<OidcClientResponse> items) { }
    @io.swagger.v3.oas.annotations.media.Schema(name = "RoleCandidate")
    public record RoleCandidate(String name, String displayName) { }
    @io.swagger.v3.oas.annotations.media.Schema(name = "RoleCandidateList")
    public record RoleCandidateList(List<RoleCandidate> items) { }
}
