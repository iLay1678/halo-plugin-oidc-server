package top.ilay.oidcserver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import run.halo.app.plugin.PluginContext;
import run.halo.app.extension.SchemeManager;

@ExtendWith(MockitoExtension.class)
class OidcServerPluginTest {

    @Mock
    PluginContext context;
    @Mock
    SchemeManager schemes;

    @InjectMocks
    OidcServerPlugin plugin;

    @Test
    void contextLoads() {
        plugin.start();
        plugin.stop();
    }
}
