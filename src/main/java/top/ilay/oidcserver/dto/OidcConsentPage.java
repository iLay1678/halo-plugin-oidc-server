package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(name = "OidcConsentPage")
public record OidcConsentPage(int page, int size, long total, List<OidcConsentResponse> items) {
}
