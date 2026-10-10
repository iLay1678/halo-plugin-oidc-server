package top.ilay.oidcserver.reconciler;

import java.time.Clock;
import org.springframework.stereotype.Component;
import run.halo.app.extension.ExtensionClient;
import top.ilay.oidcserver.extension.OidcTokenFamily;

@Component
public class FamilyCleanup extends ExpiredStateReconciler<OidcTokenFamily> {
    public FamilyCleanup(ExtensionClient client, Clock clock) { super(client, clock, OidcTokenFamily.class, new OidcTokenFamily(), value -> value.getSpec().getExpiresAt()); }
}
