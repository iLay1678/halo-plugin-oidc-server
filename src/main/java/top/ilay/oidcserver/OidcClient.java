package top.ilay.oidcserver;

import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

@Data
@EqualsAndHashCode(callSuper = true)
@GVK(group = "oidc-server.halo.run", version = "v1alpha1", kind = "OidcClient", plural = "oidcclients", singular = "oidcclient")
public class OidcClient extends AbstractExtension {
    private Spec spec;
    public enum ClientType { CONFIDENTIAL, PUBLIC }
    public enum AccessPolicy { ALL, ROLES }
    @Data
    public static class Spec {
        private String displayName;
        private String description;
        private ClientType clientType;
        private List<String> redirectUris;
        private List<String> scopes;
        private AccessPolicy accessPolicy;
        private List<String> roles;
        private boolean enabled;
        private boolean deleted;
        private String secretRef;
        private long securityVersion;
    }
}
