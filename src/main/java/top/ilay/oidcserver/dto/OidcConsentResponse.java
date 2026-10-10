package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.List;

@Schema(name = "OidcConsentResponse")
public record OidcConsentResponse(String name, String clientId, String displayName, List<String> scopes,
    Instant grantedAt, boolean revoked) {
}
