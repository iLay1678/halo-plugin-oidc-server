package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.List;
import top.ilay.oidcserver.extension.OidcClient;

@Schema(name = "OidcClientResponse", description = "应用公开配置；clientSecret 仅创建或重置密钥时返回一次")
public record OidcClientResponse(String name, String clientId, String displayName, String description,
    OidcClient.ClientType clientType, List<String> redirectUris, List<String> scopes,
    OidcClient.AccessPolicy accessPolicy, List<String> roles, boolean enabled, Instant createdAt, String clientSecret) {
    public static OidcClientResponse of(OidcClient value, String secret) {
        var spec = value.getSpec();
        return new OidcClientResponse(value.getMetadata().getName(), value.getMetadata().getName(), spec.getDisplayName(),
            spec.getDescription(), spec.getClientType(), spec.getRedirectUris(), spec.getScopes(), spec.getAccessPolicy(),
            spec.getRoles(), spec.isEnabled(), value.getMetadata().getCreationTimestamp(), secret);
    }
}
