package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(name = "RoleCandidateList")
public record RoleCandidateList(List<RoleCandidate> items) {
}
