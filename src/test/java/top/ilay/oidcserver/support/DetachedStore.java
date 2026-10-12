package top.ilay.oidcserver.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.Objects;
import java.util.Comparator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.beans.PropertyAccessorFactory;
import org.springframework.data.domain.Sort;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import run.halo.app.extension.Extension;
import run.halo.app.extension.ExtensionClient;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.ListResult;
import run.halo.app.extension.PageRequest;
import run.halo.app.extension.ReactiveExtensionClient;

/** 每次读取和写入均分离对象快照，真实执行版本比较，不依靠预设消费结果。 */
public class DetachedStore {
    public final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    final Map<String, Extension> values = new ConcurrentHashMap<>();
    private volatile FetchBarrier barrier;
    public final ReactiveExtensionClient client = (ReactiveExtensionClient) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] { ReactiveExtensionClient.class }, (proxy, method, args) -> switch (method.getName()) {
            case "fetch", "get" -> fetch((Class<?>) args[0], (String) args[1]);
            case "create" -> Mono.fromCallable(() -> save((Extension) args[0], false));
            case "update" -> Mono.fromCallable(() -> save((Extension) args[0], true));
            case "delete" -> Mono.fromCallable(() -> delete((Extension) args[0]));
            case "listBy" -> Mono.fromSupplier(() -> page((Class<?>) args[0], (ListOptions) args[1], (PageRequest) args[2]));
            case "list" -> Flux.defer(() -> Flux.fromIterable(values.values()).filter(value -> ((Class<?>) args[0]).isInstance(value))
                .map(this::copy).filter(value -> args[1] == null || ((java.util.function.Predicate<Extension>) args[1]).test(value)));
            case "toString" -> "DetachedStore";
            default -> throw new UnsupportedOperationException(method.getName());
        });
    public final ExtensionClient synchronous = (ExtensionClient) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] { ExtensionClient.class }, (proxy, method, args) -> switch (method.getName()) {
            case "fetch" -> Optional.ofNullable(snapshot((Class<? extends Extension>) args[0], (String) args[1]));
            case "create" -> { save((Extension) args[0], false); yield null; }
            case "update" -> { save((Extension) args[0], true); yield null; }
            case "delete" -> { delete((Extension) args[0]); yield null; }
            case "listBy" -> page((Class<?>) args[0], (ListOptions) args[1], (PageRequest) args[2]);
            case "listAllNames" -> listAll((Class<?>) args[0], (ListOptions) args[1], (Sort) args[2])
                .stream().map(value -> value.getMetadata().getName()).toList();
            case "toString" -> "DetachedStore.synchronous";
            default -> throw new UnsupportedOperationException(method.getName());
        });

    private ListResult<Extension> page(Class<?> type, ListOptions options, PageRequest page) {
        var all = listAll(type, options, page.getSort());
        return new ListResult<>(page.getPageNumber(), page.getPageSize(), all.size(),
            ListResult.subList(all, page.getPageNumber(), page.getPageSize()));
    }
    private List<Extension> listAll(Class<?> type, ListOptions options, Sort sort) {
        Comparator<Extension> comparator = (a, b) -> 0;
        for (var order : sort) {
            Comparator<Extension> next = Comparator.comparing(value -> (Comparable) property(value, order.getProperty()),
                Comparator.nullsFirst(Comparator.naturalOrder()));
            comparator = comparator.thenComparing(order.isAscending() ? next : next.reversed());
        }
        return values.values().stream().filter(type::isInstance).map(this::copy)
            .filter(value -> options.getFieldSelector() == null || matches(options.getFieldSelector().query(), value))
            .sorted(comparator).toList();
    }
    /** 执行查询树而非预设结果，确保分页总数也受归属条件约束。 */
    private boolean matches(Object condition, Extension value) {
        if (condition == null) { return true; }
        return switch (condition.getClass().getSimpleName()) {
            case "EmptyCondition", "AllCondition" -> true;
            case "AndCondition" -> matches(component(condition, "left"), value) && matches(component(condition, "right"), value);
            case "EqualCondition" -> Objects.equals(property(value, (String) component(condition, "indexName")), component(condition, "key"));
            case "IsNullCondition" -> property(value, (String) component(condition, "indexName")) == null;
            default -> throw new UnsupportedOperationException(condition.getClass().getName());
        };
    }
    private static Object component(Object record, String name) {
        try {
            var accessor = record.getClass().getDeclaredMethod(name); accessor.setAccessible(true);
            return accessor.invoke(record);
        } catch (ReflectiveOperationException error) { throw new IllegalStateException(error); }
    }
    private static Object property(Extension value, String name) {
        return PropertyAccessorFactory.forBeanPropertyAccess(value).getPropertyValue(name);
    }
    public synchronized Extension delete(Extension input) {
        var latest = snapshot(input.getClass(), input.getMetadata().getName());
        if (latest == null) { return input; }
        if (!Objects.equals(latest.getMetadata().getVersion(), input.getMetadata().getVersion())) {
            throw new OptimisticLockingFailureException("资源版本不一致");
        }
        if (latest.getMetadata().getDeletionTimestamp() != null) { return latest; }
        latest.getMetadata().setDeletionTimestamp(Instant.parse("2026-10-10T02:00:00Z"));
        return save(latest, true);
    }
    /** 模拟 Halo 异步 GC：删除标记和空 finalizers 缺一不可。 */
    public synchronized void collectGarbage() {
        values.entrySet().removeIf(entry -> entry.getValue().getMetadata().getDeletionTimestamp() != null
            && (entry.getValue().getMetadata().getFinalizers() == null || entry.getValue().getMetadata().getFinalizers().isEmpty()));
    }
    public void synchronizeFetch(Class<?> type, String name) { barrier = new FetchBarrier(type, name, new CyclicBarrier(2), new AtomicInteger()); }
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
    public synchronized Extension save(Extension input, boolean update) {
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
    public <E extends Extension> E add(E value) { return (E) save(value, false); }
    public <E extends Extension> E snapshot(Class<E> type, String name) { return (E) copy(values.get(key(type, name))); }
    <E extends Extension> E copy(E value) { return value == null ? null : (E) mapper.convertValue(value, value.getClass()); }
    private static String key(Class<?> type, String name) { return type.getName() + "/" + name; }
    private record FetchBarrier(Class<?> type, String name, CyclicBarrier barrier, AtomicInteger calls) { }
}
