package top.ilay.oidcserver;

import java.time.Instant;
import java.util.List;
import lombok.Data;

/** 令牌状态只保存身份、版本与摘要，不保存可使用的令牌。 */
@Data
public class GrantBinding {
    private String clientId;
    private String username;
    private String subject;
    private String issuer;
    private String consentName;
    private String consentVersion;
    private long clientVersion;
    private List<String> scopes;
    private Instant expiresAt;
}
