package top.ilay.oidcserver;

import lombok.Data;
import lombok.EqualsAndHashCode;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

@Data
@EqualsAndHashCode(callSuper = true)
@GVK(group = "oidc-server.halo.run", version = "v1alpha1", kind = "OidcTokenFamily", plural = "oidctokenfamilies", singular = "oidctokenfamily")
public class OidcTokenFamily extends AbstractExtension {
    private Spec spec;
    @Data
    @EqualsAndHashCode(callSuper = true)
    public static class Spec extends GrantBinding {
        private String currentRefreshDigest;
        private boolean revoked;
    }
}
