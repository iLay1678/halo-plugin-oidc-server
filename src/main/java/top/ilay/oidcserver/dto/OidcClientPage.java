package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(name = "OidcClientPage")
public record OidcClientPage(int page, int size, long total, List<OidcClientResponse> items) {
}
