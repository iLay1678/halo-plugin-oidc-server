package top.ilay.oidcserver;
import java.time.Clock;
import org.springframework.stereotype.Component;
import run.halo.app.extension.ExtensionClient;
@Component
public class CodeCleanup extends ExpiredStateReconciler<OidcAuthorizationCode> {
    public CodeCleanup(ExtensionClient client, Clock clock) { super(client, clock, OidcAuthorizationCode.class, new OidcAuthorizationCode(), value -> value.getSpec().getExpiresAt()); }
}
