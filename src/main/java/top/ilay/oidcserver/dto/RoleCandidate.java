package top.ilay.oidcserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "RoleCandidate")
public record RoleCandidate(String name, String displayName) {
}
