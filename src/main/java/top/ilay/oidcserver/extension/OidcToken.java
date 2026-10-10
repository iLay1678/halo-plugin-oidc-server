package top.ilay.oidcserver.extension;

import lombok.Data;
import lombok.EqualsAndHashCode;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

@Data
@EqualsAndHashCode(callSuper = true)
@GVK(group = "oidc-server.halo.run", version = "v1alpha1", kind = "OidcToken", plural = "oidctokens", singular = "oidctoken")
public class OidcToken extends AbstractExtension {
    private Spec spec;
    public enum TokenType { ACCESS, REFRESH }
    @Data
    @EqualsAndHashCode(callSuper = true)
    public static class Spec extends GrantBinding {
        private TokenType tokenType;
        private String familyName;
        private boolean revoked;
    }
}
