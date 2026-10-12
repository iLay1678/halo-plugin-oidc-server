package top.ilay.oidcserver.reconciler;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import run.halo.app.core.extension.User;
import run.halo.app.extension.ExtensionClient;
import run.halo.app.extension.ExtensionUtil;
import run.halo.app.extension.controller.Controller;
import run.halo.app.extension.controller.ControllerBuilder;
import run.halo.app.extension.controller.Reconciler;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.service.OidcIdentityService;

/** 清理升级前或插件停用期间遗留的无主授权，也处理删除过程中迟到的写入。 */
@Component
@RequiredArgsConstructor
public class ConsentCleanup implements Reconciler<Reconciler.Request> {
    private final ExtensionClient client;

    @Override
    public Result reconcile(Request request) {
        client.fetch(OidcConsent.class, request.name()).filter(value -> !ExtensionUtil.isDeleted(value))
            .ifPresent(consent -> {
                var spec = consent.getSpec();
                var owner = spec == null || spec.getUsername() == null ? java.util.Optional.<User>empty()
                    : client.fetch(User.class, spec.getUsername());
                var valid = owner.filter(user -> !ExtensionUtil.isDeleted(user))
                    .filter(user -> user.getMetadata().getCreationTimestamp() != null)
                    .filter(user -> OidcIdentityService.subject(user).equals(spec.getSubject())).isPresent();
                if (!valid) { client.delete(consent); }
            });
        return Result.doNotRetry();
    }

    @Override
    public Controller setupWith(ControllerBuilder builder) {
        return builder.extension(new OidcConsent()).workerCount(1).syncAllOnStart(true).build();
    }
}
