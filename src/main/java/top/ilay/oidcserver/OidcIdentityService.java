package top.ilay.oidcserver;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.Role;
import run.halo.app.core.extension.User;
import run.halo.app.core.user.service.RoleService;
import run.halo.app.extension.Extension;
import run.halo.app.extension.ReactiveExtensionClient;

@Service
@RequiredArgsConstructor
public class OidcIdentityService {
    private final ReactiveExtensionClient client;
    private final RoleService roles;

    public Mono<User> current() {
        return ReactiveSecurityContextHolder.getContext().map(context -> context.getAuthentication())
            .filter(OidcIdentityService::complete).flatMap(auth -> user(auth.getName()))
            .switchIfEmpty(Mono.error(new OAuthError("login_required", "请完成 Halo 登录及两步验证", HttpStatus.UNAUTHORIZED)));
    }
    public Mono<User> manager() {
        return manager(List.of(
            new Permission("clients", "get"), new Permission("clients", "list"),
            new Permission("clients", "create"), new Permission("clients", "update"),
            new Permission("clients", "delete"), new Permission("clients/enable", "create"),
            new Permission("clients/disable", "create"), new Permission("clients/reset-secret", "create"),
            new Permission("roles", "list")));
    }
    /** 按具体管理动作检查权限；不同规则拆分 verbs 时仍可合并判断。 */
    public Mono<User> manager(String resource, String verb) {
        return manager(List.of(new Permission(resource, verb)));
    }
    private Mono<User> manager(List<Permission> required) {
        return current().flatMap(user -> roles.getRolesByUsername(user.getMetadata().getName()).collect(java.util.stream.Collectors.toSet())
            .flatMapMany(roles::listPermissions).filter(OidcIdentityService::active)
            .flatMapIterable(role -> role.getRules() == null ? java.util.List.<Role.PolicyRule>of() : role.getRules())
            .collectList().flatMap(rules -> required.stream().allMatch(permission -> rules.stream().anyMatch(rule -> matches(rule, permission)))
                ? Mono.just(user)
                : Mono.error(new OAuthError("access_denied", "需要 OIDC 应用管理权限", HttpStatus.FORBIDDEN))));
    }
    private static boolean matches(Role.PolicyRule rule, Permission required) {
        return contains(rule.getApiGroups(), "console.api.oidc-server.halo.run")
            && contains(rule.getResources(), required.resource()) && contains(rule.getVerbs(), required.verb())
            && (rule.getResourceNames() == null || rule.getResourceNames().length == 0);
    }
    private record Permission(String resource, String verb) { }
    private static boolean contains(String[] values, String target) {
        return values != null && java.util.Arrays.stream(values).anyMatch(value -> value.equals("*") || value.equals(target));
    }
    static boolean complete(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)
            && !auth.getClass().getSimpleName().equals("TwoFactorAuthentication")
            && !"anonymousUser".equals(auth.getName());
    }
    public Mono<User> user(String username) {
        return client.fetch(User.class, username).filter(OidcIdentityService::eligible)
            .switchIfEmpty(Mono.error(OAuthError.grant()));
    }
    public Mono<User> allowed(OidcClient application, String username) {
        return user(username).flatMap(user -> {
            if (application.getSpec().getAccessPolicy() == OidcClient.AccessPolicy.ALL) { return Mono.just(user); }
            if (application.getSpec().getAccessPolicy() != OidcClient.AccessPolicy.ROLES
                || application.getSpec().getRoles() == null || application.getSpec().getRoles().isEmpty()) { return Mono.error(OAuthError.grant()); }
            // 每次从角色服务读取当前绑定，避免会话内旧 authorities 延长资格。
            return roles.getRolesByUsername(username)
                .filter(application.getSpec().getRoles()::contains)
                .concatMap(name -> client.fetch(Role.class, name).filter(OidcIdentityService::selectableRole))
                .hasElements().flatMap(allowed -> allowed ? Mono.just(user) : Mono.error(new OAuthError("access_denied", "当前用户不符合应用访问策略", HttpStatus.FORBIDDEN)));
        });
    }
    static boolean active(Extension value) { return value != null && value.getMetadata() != null && value.getMetadata().getDeletionTimestamp() == null; }
    static boolean eligible(User user) {
        return active(user) && user.getSpec() != null && !Boolean.TRUE.equals(user.getSpec().getDisabled())
            && !"true".equals(labels(user).get(User.HIDDEN_USER_LABEL));
    }
    static boolean selectableRole(Role role) {
        return active(role) && !Set.of("anonymous", "authenticated").contains(role.getMetadata().getName())
            && !"true".equals(labels(role).get(Role.TEMPLATE_LABEL_NAME)) && !"true".equals(labels(role).get(Role.HIDDEN_LABEL_NAME));
    }
    private static Map<String, String> labels(Extension value) { return value.getMetadata().getLabels() == null ? Map.of() : value.getMetadata().getLabels(); }
    static String subject(User user) {
        // 绑定账户创建时刻，用户名删除后重建不会继承旧主体标识。
        return OidcCrypto.digest("oidc-sub\0" + user.getMetadata().getName() + "\0" + user.getMetadata().getCreationTimestamp());
    }
    static Map<String, Object> claims(User user, java.util.List<String> scopes) {
        var result = new LinkedHashMap<String, Object>();
        result.put("sub", subject(user));
        if (scopes.contains("profile")) {
            result.put("preferred_username", user.getMetadata().getName());
            var name = user.getSpec().getDisplayName();
            result.put("name", name == null || name.isBlank() ? user.getMetadata().getName() : name);
            var avatar = user.getSpec().getAvatar();
            try {
                if (avatar != null && !avatar.isBlank()) {
                    var uri = URI.create(avatar);
                    if (uri.isAbsolute() && uri.getHost() != null && uri.getUserInfo() == null
                        && Set.of("https", "http").contains(uri.getScheme())) { result.put("picture", avatar); }
                }
            } catch (IllegalArgumentException ignored) { /* 无效头像不影响身份声明。 */ }
        }
        if (scopes.contains("email") && user.getSpec().getEmail() != null) {
            result.put("email", user.getSpec().getEmail()); result.put("email_verified", user.getSpec().isEmailVerified());
        }
        return result;
    }
}
