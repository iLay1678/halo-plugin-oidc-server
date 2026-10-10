package top.ilay.oidcserver.extension;

import lombok.Data;
import lombok.EqualsAndHashCode;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

@Data
@EqualsAndHashCode(callSuper = true)
@GVK(group = "oidc-server.halo.run", version = "v1alpha1", kind = "OidcAuthorizationCode", plural = "oidcauthorizationcodes", singular = "oidcauthorizationcode")
public class OidcAuthorizationCode extends AbstractExtension {
    private Spec spec;
    @Data
    @EqualsAndHashCode(callSuper = true)
    public static class Spec extends GrantBinding {
        private String redirectUri;
        private String challenge;
        private String nonce;
        private boolean consumed;
    }
}
