package top.ilay.oidcserver.reconciler;

import java.time.Clock;
import org.springframework.stereotype.Component;
import run.halo.app.extension.ExtensionClient;
import top.ilay.oidcserver.extension.OidcAuthorizationCode;

@Component
public class CodeCleanup extends ExpiredStateReconciler<OidcAuthorizationCode> {
    public CodeCleanup(ExtensionClient client, Clock clock) { super(client, clock, OidcAuthorizationCode.class, new OidcAuthorizationCode(), value -> value.getSpec().getExpiresAt()); }
}
