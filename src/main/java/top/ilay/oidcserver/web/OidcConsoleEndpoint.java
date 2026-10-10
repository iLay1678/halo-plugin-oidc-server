package top.ilay.oidcserver.web;

import static org.springdoc.core.fn.builders.apiresponse.Builder.responseBuilder;
import static org.springdoc.core.fn.builders.parameter.Builder.parameterBuilder;
import static org.springdoc.core.fn.builders.requestbody.Builder.requestBodyBuilder;

import io.swagger.v3.oas.annotations.enums.ParameterIn;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.fn.builders.operation.Builder;
import org.springdoc.webflux.core.fn.SpringdocRouteBuilder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.endpoint.CustomEndpoint;
import run.halo.app.extension.GroupVersion;
import top.ilay.oidcserver.dto.OidcClientPage;
import top.ilay.oidcserver.dto.OidcClientRequest;
import top.ilay.oidcserver.dto.OidcClientResponse;
import top.ilay.oidcserver.dto.RoleCandidateList;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.service.OidcClientService;
import top.ilay.oidcserver.service.OidcIdentityService;

@Component
@RequiredArgsConstructor
public class OidcConsoleEndpoint implements CustomEndpoint {
    private static final String TAG = "OidcV1alpha1Console";
    private final OidcClientService clients;
    private final OidcIdentityService identity;
    @Override
    public RouterFunction<ServerResponse> endpoint() {
        return SpringdocRouteBuilder.route()
            .GET("/clients", request -> respond(identity.manager("clients", "list").then(clients.list(number(request, "page", 1), number(request, "size", 20), request.queryParam("keyword").orElse("")))),
                builder -> {
                    page(builder.operationId("listOidcClients").tag(TAG).description("分页搜索应用公开配置"));
                    builder.parameter(parameterBuilder().name("keyword").in(ParameterIn.QUERY).implementation(String.class).description("应用名称关键词"))
                        .response(responseBuilder().implementation(OidcClientPage.class));
                })
            .GET("/clients/{name}", request -> respond(identity.manager("clients", "get").then(clients.get(request.pathVariable("name"))).map(value -> OidcClientResponse.of(value, null))),
                builder -> named(builder, "getOidcClient", "查询应用公开配置"))
            .POST("/clients", request -> respond(identity.manager("clients", "create").then(body(request)).flatMap(clients::create)), builder -> write(builder, "createOidcClient", "注册应用；机密客户端仅返回一次新密钥", false))
            .PUT("/clients/{name}", request -> respond(identity.manager("clients", "update").then(body(request)).flatMap(body -> clients.update(request.pathVariable("name"), body))),
                builder -> write(builder, "updateOidcClient", "更新公开配置并使历史授权码与令牌失效", true))
            .POST("/clients/{name}/disable", request -> respond(identity.manager("clients/disable", "create").then(clients.state(request.pathVariable("name"), false, false))),
                builder -> named(builder, "disableOidcClient", "停用应用并使历史授权码与令牌失效"))
            .POST("/clients/{name}/enable", request -> respond(identity.manager("clients/enable", "create").then(clients.state(request.pathVariable("name"), true, false))),
                builder -> named(builder, "enableOidcClient", "启用应用；历史令牌不会恢复"))
            .DELETE("/clients/{name}", request -> respond(identity.manager("clients", "delete").then(clients.state(request.pathVariable("name"), false, true))),
                builder -> named(builder, "deleteOidcClient", "删除应用并使历史授权码与令牌失效"))
            .POST("/clients/{name}/reset-secret", request -> respond(identity.manager("clients/reset-secret", "create").then(clients.reset(request.pathVariable("name")))),
                builder -> named(builder, "resetOidcClientSecret", "重置机密客户端密钥，仅返回一次新密钥"))
            .GET("/roles", request -> respond(identity.manager("roles", "list").then(clients.roles(request.queryParam("keyword").orElse("")))),
                builder -> builder.operationId("listOidcRoles").tag(TAG).description("可选择的有效 Halo 角色，最多 100 条")
                    .parameter(parameterBuilder().name("keyword").in(ParameterIn.QUERY).implementation(String.class))
                    .response(responseBuilder().implementation(RoleCandidateList.class)))
            .build();
    }
    static void page(Builder builder) {
        builder.parameter(parameterBuilder().name("page").in(ParameterIn.QUERY).implementation(Integer.class).description("页码，从 1 开始，默认 1"))
            .parameter(parameterBuilder().name("size").in(ParameterIn.QUERY).implementation(Integer.class).description("每页 1–100 条，默认 20"));
    }
    private static void named(Builder builder, String operation, String description) {
        builder.operationId(operation).tag(TAG).description(description)
            .parameter(parameterBuilder().name("name").in(ParameterIn.PATH).required(true).implementation(String.class).description("服务端生成的客户端 ID"))
            .response(responseBuilder().implementation(OidcClientResponse.class));
    }
    private static void write(Builder builder, String operation, String description, boolean named) {
        if (named) { named(builder, operation, description); }
        else { builder.operationId(operation).tag(TAG).description(description).response(responseBuilder().implementation(OidcClientResponse.class)); }
        builder.requestBody(requestBodyBuilder().required(true).implementation(OidcClientRequest.class));
    }
    static int number(ServerRequest request, String name, int fallback) {
        try { return Integer.parseInt(request.queryParam(name).orElse(String.valueOf(fallback))); }
        catch (NumberFormatException error) { throw OAuthError.invalid(name + " 必须是整数"); }
    }
    private static Mono<OidcClientRequest> body(ServerRequest request) { return request.bodyToMono(OidcClientRequest.class).switchIfEmpty(Mono.error(OAuthError.invalid("请求正文不能为空"))); }
    static Mono<ServerResponse> respond(Mono<?> publisher) {
        return publisher.flatMap(value -> ServerResponse.ok().cacheControl(org.springframework.http.CacheControl.noStore()).bodyValue(value))
            .onErrorResume(OAuthError.class, error -> ServerResponse.status(error.status()).cacheControl(org.springframework.http.CacheControl.noStore()).bodyValue(error.body()));
    }
    @Override public GroupVersion groupVersion() { return new GroupVersion("console.api.oidc-server.halo.run", "v1alpha1"); }
}
