package top.ilay.oidcserver;

import java.time.Instant;
import org.springframework.stereotype.Component;
import run.halo.app.extension.Scheme;
import run.halo.app.extension.SchemeManager;
import run.halo.app.extension.index.IndexSpecs;
import run.halo.app.plugin.BasePlugin;
import run.halo.app.plugin.PluginContext;
import top.ilay.oidcserver.extension.OidcAuthorizationCode;
import top.ilay.oidcserver.extension.OidcClient;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.extension.OidcToken;
import top.ilay.oidcserver.extension.OidcTokenFamily;

/** 注册持久化状态与索引；密钥不会随停用删除。 */
@Component
public class OidcServerPlugin extends BasePlugin {

    private final SchemeManager schemes;
    public OidcServerPlugin(PluginContext pluginContext, SchemeManager schemes) {
        super(pluginContext);
        this.schemes = schemes;
    }

    @Override
    public void start() {
        schemes.register(OidcClient.class, indexes -> {
            indexes.add(IndexSpecs.<OidcClient, String>single("spec.displayName", String.class).indexFunc(value -> value.getSpec().getDisplayName()));
            indexes.add(IndexSpecs.<OidcClient, Boolean>single("spec.deleted", Boolean.class).indexFunc(value -> value.getSpec().isDeleted()));
        });
        schemes.register(OidcConsent.class, indexes -> {
            indexes.add(IndexSpecs.<OidcConsent, String>single("spec.username", String.class).indexFunc(value -> value.getSpec().getUsername()));
            indexes.add(IndexSpecs.<OidcConsent, String>single("spec.clientId", String.class).indexFunc(value -> value.getSpec().getClientId()));
            indexes.add(IndexSpecs.<OidcConsent, Boolean>single("spec.revoked", Boolean.class).indexFunc(value -> value.getSpec().isRevoked()));
            indexes.add(IndexSpecs.<OidcConsent, Instant>single("spec.grantedAt", Instant.class).indexFunc(value -> value.getSpec().getGrantedAt()));
        });
        schemes.register(OidcAuthorizationCode.class, indexes -> {
            indexes.add(IndexSpecs.<OidcAuthorizationCode, String>single("spec.username", String.class).indexFunc(value -> value.getSpec().getUsername()));
            indexes.add(IndexSpecs.<OidcAuthorizationCode, String>single("spec.clientId", String.class).indexFunc(value -> value.getSpec().getClientId()));
            indexes.add(IndexSpecs.<OidcAuthorizationCode, Instant>single("spec.expiresAt", Instant.class).indexFunc(value -> value.getSpec().getExpiresAt()));
        });
        schemes.register(OidcToken.class, indexes -> {
            indexes.add(IndexSpecs.<OidcToken, String>single("spec.username", String.class).indexFunc(value -> value.getSpec().getUsername()));
            indexes.add(IndexSpecs.<OidcToken, String>single("spec.clientId", String.class).indexFunc(value -> value.getSpec().getClientId()));
            indexes.add(IndexSpecs.<OidcToken, Instant>single("spec.expiresAt", Instant.class).indexFunc(value -> value.getSpec().getExpiresAt()));
        });
        schemes.register(OidcTokenFamily.class, indexes -> {
            indexes.add(IndexSpecs.<OidcTokenFamily, String>single("spec.username", String.class).indexFunc(value -> value.getSpec().getUsername()));
            indexes.add(IndexSpecs.<OidcTokenFamily, String>single("spec.clientId", String.class).indexFunc(value -> value.getSpec().getClientId()));
            indexes.add(IndexSpecs.<OidcTokenFamily, Instant>single("spec.expiresAt", Instant.class).indexFunc(value -> value.getSpec().getExpiresAt()));
        });
    }

    @Override
    public void stop() {
        for (var type : java.util.List.of(OidcTokenFamily.class, OidcToken.class, OidcAuthorizationCode.class, OidcConsent.class, OidcClient.class)) {
            schemes.unregister(Scheme.buildFromType(type));
        }
    }
}
