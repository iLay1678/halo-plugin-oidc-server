package top.ilay.oidcserver;
import java.time.Clock;
import org.springframework.stereotype.Component;
import run.halo.app.extension.ExtensionClient;
@Component
public class TokenCleanup extends ExpiredStateReconciler<OidcToken> {
    public TokenCleanup(ExtensionClient client, Clock clock) { super(client, clock, OidcToken.class, new OidcToken(), value -> value.getSpec().getExpiresAt()); }
}
