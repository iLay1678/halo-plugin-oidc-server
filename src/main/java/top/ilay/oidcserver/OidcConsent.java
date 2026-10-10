package top.ilay.oidcserver;

import java.time.Instant;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

@Data
@EqualsAndHashCode(callSuper = true)
@GVK(group = "oidc-server.halo.run", version = "v1alpha1", kind = "OidcConsent", plural = "oidcconsents", singular = "oidcconsent")
public class OidcConsent extends AbstractExtension {
    private Spec spec;
    @Data
    public static class Spec {
        private String username;
        private String subject;
        private String clientId;
        private List<String> scopes;
        private String authorizationVersion;
        private long clientVersion;
        private boolean revoked;
        private Instant grantedAt;
    }
}
