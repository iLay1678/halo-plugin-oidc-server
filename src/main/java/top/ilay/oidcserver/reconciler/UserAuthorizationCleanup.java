package top.ilay.oidcserver.reconciler;

import java.time.Duration;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.pf4j.Extension;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.User;
import run.halo.app.core.user.service.UserPreCreatingHandler;
import run.halo.app.extension.ExtensionClient;
import run.halo.app.extension.ExtensionUtil;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.PageRequestImpl;
import run.halo.app.extension.controller.Controller;
import run.halo.app.extension.controller.ControllerBuilder;
import run.halo.app.extension.controller.Reconciler;
import run.halo.app.extension.index.query.Queries;
import top.ilay.oidcserver.extension.OidcAuthorizationCode;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.extension.OidcToken;
import top.ilay.oidcserver.extension.OidcTokenFamily;
import top.ilay.oidcserver.service.OidcIdentityService;

/** 保持用户的删除保护，直到关联 OIDC 状态被垃圾回收器实际删除。 */
@Component
@Extension
@RequiredArgsConstructor
public class UserAuthorizationCleanup implements Reconciler<Reconciler.Request>, UserPreCreatingHandler {
    private final ExtensionClient client;
    private static final Set<String> FINALIZERS = Set.of(OidcIdentityService.USER_FINALIZER);

    @Override
    public Mono<Void> preCreating(User user) {
        return Mono.fromRunnable(() -> ExtensionUtil.addFinalizers(user.getMetadata(), FINALIZERS));
    }

    @Override
    public Result reconcile(Request request) {
        var optional = client.fetch(User.class, request.name());
        if (optional.isEmpty()) { return Result.doNotRetry(); }
        var user = optional.get();
        if (!ExtensionUtil.isDeleted(user)) {
            if (ExtensionUtil.addFinalizers(user.getMetadata(), FINALIZERS)) { client.update(user); }
            return Result.doNotRetry();
        }
        boolean pending = false;
        for (var type : java.util.List.of(OidcConsent.class, OidcAuthorizationCode.class,
            OidcToken.class, OidcTokenFamily.class)) {
            pending |= deleteBatch(type, request.name());
        }
        if (pending) { return Result.requeue(Duration.ofSeconds(1)); }
        if (ExtensionUtil.removeFinalizers(user.getMetadata(), FINALIZERS)) { client.update(user); }
        return Result.doNotRetry();
    }

    private <E extends run.halo.app.extension.Extension> boolean deleteBatch(Class<E> type, String username) {
        var options = ListOptions.builder().andQuery(Queries.equal("spec.username", username)).build();
        var records = client.listBy(type, options, PageRequestImpl.of(1, 100, Sort.by("metadata.name")));
        for (var record : records.getItems()) {
            if (!ExtensionUtil.isDeleted(record)) { client.delete(record); }
        }
        // 包含已标记删除的记录；仅发出删除请求不代表清理完成。
        return records.getTotal() > 0;
    }

    /** 停用时释放本插件的保护，避免控制器停止后阻塞 Halo 用户删除。 */
    public void releaseFinalizers() {
        for (var name : client.listAllNames(User.class, new ListOptions(), Sort.by("metadata.name"))) {
            for (int attempt = 0; attempt < 4; attempt++) {
                try {
                    client.fetch(User.class, name).ifPresent(user -> {
                        if (ExtensionUtil.removeFinalizers(user.getMetadata(), FINALIZERS)) { client.update(user); }
                    });
                    break;
                } catch (OptimisticLockingFailureException error) {
                    if (attempt == 3) { throw error; }
                }
            }
        }
    }

    @Override
    public Controller setupWith(ControllerBuilder builder) {
        return builder.extension(new User()).workerCount(1).syncAllOnStart(true).build();
    }
}
