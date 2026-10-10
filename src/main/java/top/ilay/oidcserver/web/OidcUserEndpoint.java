package top.ilay.oidcserver.web;

import static org.springdoc.core.fn.builders.apiresponse.Builder.responseBuilder;
import static org.springdoc.core.fn.builders.parameter.Builder.parameterBuilder;

import io.swagger.v3.oas.annotations.enums.ParameterIn;
import lombok.RequiredArgsConstructor;
import org.springdoc.webflux.core.fn.SpringdocRouteBuilder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import run.halo.app.core.extension.endpoint.CustomEndpoint;
import run.halo.app.extension.GroupVersion;
import top.ilay.oidcserver.dto.OidcConsentPage;
import top.ilay.oidcserver.dto.OidcConsentResponse;
import top.ilay.oidcserver.service.OidcConsentService;
import top.ilay.oidcserver.service.OidcIdentityService;

@Component
@RequiredArgsConstructor
public class OidcUserEndpoint implements CustomEndpoint {
    private final OidcIdentityService identity;
    private final OidcConsentService consents;
    @Override public RouterFunction<ServerResponse> endpoint() {
        return SpringdocRouteBuilder.route()
            .GET("/authorizations", request -> OidcConsoleEndpoint.respond(identity.current().flatMap(user ->
                consents.list(user.getMetadata().getName(), OidcConsoleEndpoint.number(request, "page", 1), OidcConsoleEndpoint.number(request, "size", 20)))),
                builder -> {
                    OidcConsoleEndpoint.page(builder.operationId("listMyOidcAuthorizations").tag("OidcV1alpha1Uc").description("分页查询当前用户的应用授权"));
                    builder.response(responseBuilder().implementation(OidcConsentPage.class));
                })
            .POST("/authorizations/{name}/revoke", request -> OidcConsoleEndpoint.respond(identity.current().flatMap(user ->
                consents.revoke(request.pathVariable("name"), user.getMetadata().getName()))),
                builder -> builder.operationId("revokeMyOidcAuthorization").tag("OidcV1alpha1Uc").description("撤销当前用户的授权；所有历史授权码与令牌立即失效")
                    .parameter(parameterBuilder().name("name").in(ParameterIn.PATH).required(true).implementation(String.class).description("授权记录名称"))
                    .response(responseBuilder().implementation(OidcConsentResponse.class)))
            .build();
    }
    @Override public GroupVersion groupVersion() { return new GroupVersion("uc.api.oidc-server.halo.run", "v1alpha1"); }
}
