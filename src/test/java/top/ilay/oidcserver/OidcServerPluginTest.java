package top.ilay.oidcserver;

import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import run.halo.app.plugin.PluginContext;
import run.halo.app.extension.SchemeManager;
import top.ilay.oidcserver.reconciler.UserAuthorizationCleanup;

@ExtendWith(MockitoExtension.class)
class OidcServerPluginTest {

    @Mock
    PluginContext context;
    @Mock
    SchemeManager schemes;
    @Mock
    UserAuthorizationCleanup userCleanup;

    @InjectMocks
    OidcServerPlugin plugin;

    @Test
    void contextLoads() {
        plugin.start();
        plugin.stop();
        verify(userCleanup).releaseFinalizers();
    }
}
