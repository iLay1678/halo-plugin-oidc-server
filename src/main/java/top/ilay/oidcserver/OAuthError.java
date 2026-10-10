package top.ilay.oidcserver;

import java.util.Map;
import org.springframework.http.HttpStatus;

public class OAuthError extends RuntimeException {
    private final String code;
    private final HttpStatus status;
    public OAuthError(String code, String message) { this(code, message, HttpStatus.BAD_REQUEST); }
    public OAuthError(String code, String message, HttpStatus status) {
        super(message);
        this.code = code;
        this.status = status;
    }
    public String code() { return code; }
    public HttpStatus status() { return status; }
    public Map<String, String> body() { return Map.of("error", code, "error_description", getMessage()); }
    public static OAuthError invalid(String message) { return new OAuthError("invalid_request", message); }
    public static OAuthError grant() { return new OAuthError("invalid_grant", "授权无效、已撤销或已过期"); }
    public static OAuthError client() { return new OAuthError("invalid_client", "客户端认证失败", HttpStatus.UNAUTHORIZED); }
    public static OAuthError token() { return new OAuthError("invalid_token", "访问令牌无效、已撤销或已过期", HttpStatus.UNAUTHORIZED); }
}
