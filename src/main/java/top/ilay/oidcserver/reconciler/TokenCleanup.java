package top.ilay.oidcserver.reconciler;

import java.time.Clock;
import org.springframework.stereotype.Component;
import run.halo.app.extension.ExtensionClient;
import top.ilay.oidcserver.extension.OidcToken;

@Component
public class TokenCleanup extends ExpiredStateReconciler<OidcToken> {
    public TokenCleanup(ExtensionClient client, Clock clock) { super(client, clock, OidcToken.class, new OidcToken(), value -> value.getSpec().getExpiresAt()); }
}
