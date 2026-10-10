package top.ilay.oidcserver.reconciler;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.ExtensionClient;
import run.halo.app.extension.controller.Controller;
import run.halo.app.extension.controller.ControllerBuilder;
import run.halo.app.extension.controller.Reconciler;
import top.ilay.oidcserver.util.ExtensionUtils;

/** 清理仅在 Halo 控制器工作线程执行；协议独立检查有效期。 */
abstract class ExpiredStateReconciler<E extends AbstractExtension> implements Reconciler<Reconciler.Request> {
    private final ExtensionClient client;
    private final Clock clock;
    private final Class<E> type;
    private final E prototype;
    private final Function<E, Instant> expires;
    ExpiredStateReconciler(ExtensionClient client, Clock clock, Class<E> type, E prototype, Function<E, Instant> expires) {
        this.client = client; this.clock = clock; this.type = type; this.prototype = prototype; this.expires = expires;
    }
    @Override public Result reconcile(Request request) {
        var value = client.fetch(type, request.name());
        if (value.isEmpty() || !ExtensionUtils.active(value.get())) { return Result.doNotRetry(); }
        var expiry = expires.apply(value.get());
        if (expiry == null) { return Result.doNotRetry(); }
        var delay = Duration.between(clock.instant(), expiry.plus(Duration.ofDays(1)));
        if (!delay.isNegative() && !delay.isZero()) { return Result.requeue(delay.compareTo(Duration.ofMinutes(30)) > 0 ? Duration.ofMinutes(30) : delay); }
        client.delete(value.get()); return Result.doNotRetry();
    }
    @Override public Controller setupWith(ControllerBuilder builder) { return builder.extension(prototype).workerCount(1).syncAllOnStart(true).build(); }
}
