package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.protocol.OidcValidation;

@Schema(name = "OidcClientRequest", description = "应用公开配置；客户端类型创建后不可修改")
public record OidcClientRequest(String displayName, String description, OidcClient.ClientType clientType,
    List<String> redirectUris, List<String> scopes, OidcClient.AccessPolicy accessPolicy, List<String> roles, boolean enabled) {
    public void validate() {
        if (displayName == null || displayName.isBlank() || displayName.length() > 120
            || description != null && description.length() > 2000) { throw OAuthError.invalid("应用名称或说明长度无效"); }
        if (clientType == null || accessPolicy == null || redirectUris == null || redirectUris.isEmpty() || redirectUris.size() > 20) { throw OAuthError.invalid("客户端类型、访问策略和回调地址不能为空"); }
        redirectUris.forEach(OidcValidation::redirect);
        if (scopes == null || scopes.isEmpty() || !scopes.contains("openid") || !OidcValidation.SCOPES.containsAll(scopes)) { throw OAuthError.invalid("应用权限必须包含 openid 且全部属于受支持范围"); }
        if (accessPolicy == OidcClient.AccessPolicy.ROLES && (roles == null || roles.isEmpty())) { throw OAuthError.invalid("指定角色策略至少选择一个角色"); }
        if (roles != null && roles.size() > 100) { throw OAuthError.invalid("角色数量超出限制"); }
    }
    public void apply(OidcClient.Spec spec) {
        spec.setDisplayName(displayName.trim()); spec.setDescription(description == null ? "" : description.trim());
        spec.setClientType(clientType); spec.setRedirectUris(redirectUris.stream().distinct().toList());
        spec.setScopes(scopes.stream().distinct().sorted().toList()); spec.setAccessPolicy(accessPolicy);
        spec.setRoles(accessPolicy == OidcClient.AccessPolicy.ALL ? List.of() : roles.stream().distinct().toList());
        spec.setEnabled(enabled);
    }
}
