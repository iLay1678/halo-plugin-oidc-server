package top.ilay.oidcserver.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OidcConfiguration {
    @Bean public Clock oidcClock() { return Clock.systemUTC(); }
}
