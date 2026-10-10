package top.ilay.oidcserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.dao.OptimisticLockingFailureException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import run.halo.app.extension.Extension;
import run.halo.app.extension.ReactiveExtensionClient;

/** 每次读取和写入均分离对象快照，真实执行版本比较，不依靠预设消费结果。 */
class DetachedStore {
    final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    final Map<String, Extension> values = new ConcurrentHashMap<>();
    private volatile FetchBarrier barrier;
    final ReactiveExtensionClient client = (ReactiveExtensionClient) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] { ReactiveExtensionClient.class }, (proxy, method, args) -> switch (method.getName()) {
            case "fetch", "get" -> fetch((Class<?>) args[0], (String) args[1]);
            case "create" -> Mono.fromCallable(() -> save((Extension) args[0], false));
            case "update" -> Mono.fromCallable(() -> save((Extension) args[0], true));
            case "list" -> Flux.defer(() -> Flux.fromIterable(values.values()).filter(value -> ((Class<?>) args[0]).isInstance(value))
                .map(this::copy).filter(value -> args[1] == null || ((java.util.function.Predicate<Extension>) args[1]).test(value)));
            case "toString" -> "DetachedStore";
            default -> throw new UnsupportedOperationException(method.getName());
        });
    void synchronizeFetch(Class<?> type, String name) { barrier = new FetchBarrier(type, name, new CyclicBarrier(2), new AtomicInteger()); }
    Mono<Extension> fetch(Class<?> type, String name) {
        return Mono.fromCallable(() -> {
            var value = values.get(key(type, name));
            var detached = value == null ? null : copy(value);
            var wait = barrier;
            if (wait != null && wait.type() == type && wait.name().equals(name) && wait.calls().incrementAndGet() <= 2) {
                wait.barrier().await(5, TimeUnit.SECONDS);
            }
            return detached;
        }).subscribeOn(Schedulers.boundedElastic());
    }
    synchronized Extension save(Extension input, boolean update) {
        var key = key(input.getClass(), input.getMetadata().getName());
        var previous = values.get(key);
        if (update && (previous == null || !java.util.Objects.equals(input.getMetadata().getVersion(), previous.getMetadata().getVersion()))
            || !update && previous != null) { throw new OptimisticLockingFailureException("资源版本不一致"); }
        var saved = copy(input);
        saved.getMetadata().setVersion(previous == null ? 1L : previous.getMetadata().getVersion() + 1);
        if (saved.getMetadata().getCreationTimestamp() == null) { saved.getMetadata().setCreationTimestamp(Instant.parse("2026-10-10T00:00:00Z")); }
        values.put(key, copy(saved));
        return saved;
    }
    <E extends Extension> E add(E value) { return (E) save(value, false); }
    <E extends Extension> E snapshot(Class<E> type, String name) { return (E) copy(values.get(key(type, name))); }
    <E extends Extension> E copy(E value) { return (E) mapper.convertValue(value, value.getClass()); }
    private static String key(Class<?> type, String name) { return type.getName() + "/" + name; }
    private record FetchBarrier(Class<?> type, String name, CyclicBarrier barrier, AtomicInteger calls) { }
}
