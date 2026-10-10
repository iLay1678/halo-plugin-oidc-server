package top.ilay.oidcserver;

import java.net.URI;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.util.HtmlUtils;
import top.ilay.oidcserver.OidcValidation.AuthorizationRequest;

/** 授权确认页的独立视图，动态文本统一转义，保持无脚本表单提交。 */
final class OidcConsentPage {
    private static final Map<String, String> SCOPE_LABELS = Map.of(
        "openid", "基本身份",
        "profile", "个人资料",
        "email", "邮箱",
        "offline_access", "保持授权（允许应用在配置的有效期内刷新令牌）");

    private OidcConsentPage() { }

    static String render(AuthorizationRequest request, OidcClient client, String username,
                         CsrfToken token, String requestId) {
        var scopes = request.scopes().stream()
            .map(scope -> "<li><span class=\"scope-dot\" aria-hidden=\"true\"></span><span>"
                + escape(SCOPE_LABELS.get(scope)) + "</span></li>")
            .collect(Collectors.joining());
        var description = client.getSpec().getDescription();
        if (description == null || description.isBlank()) {
            description = "此应用请求访问你的账户信息。";
        }
        return TEMPLATE.formatted(escape(client.getSpec().getDisplayName()), escape(description),
            escape(username), escape(URI.create(request.redirectUri()).getAuthority()), scopes,
            escape(token.getParameterName()), escape(token.getToken()), escape(requestId));
    }

    private static String escape(String value) {
        return HtmlUtils.htmlEscape(value == null ? "" : value);
    }

    private static final String TEMPLATE = """
                <!doctype html>
                <html lang="zh-CN">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width,initial-scale=1">
                  <meta name="theme-color" content="#0b73e0">
                  <title>确认应用授权</title>
                  <style>
                    :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
                    * { box-sizing: border-box; }
                    body { min-height: 100vh; margin: 0; padding: 28px 16px; display: grid; place-items: center; color: #14213d; background: radial-gradient(circle at 15%% 10%%, #d9efff 0, transparent 34%%), linear-gradient(145deg, #f3f8ff 0%%, #eaf2fc 100%%); }
                    .shell { width: min(100%%, 520px); }
                    main { overflow: hidden; border: 1px solid rgb(148 174 205 / 42%%); border-radius: 22px; background: rgb(255 255 255 / 94%%); box-shadow: 0 24px 70px rgb(36 79 122 / 16%%); }
                    .hero { padding: 30px 32px 24px; text-align: center; background: linear-gradient(180deg, #fafdff 0%%, #f1f7ff 100%%); border-bottom: 1px solid #e2edf9; }
                    .app-icon { width: 62px; height: 62px; display: grid; place-items: center; margin: 0 auto 16px; color: #0756bc; border: 1px solid #c9e1fb; border-radius: 18px; background: #e5f2ff; }
                    .app-icon svg { width: 30px; height: 30px; }
                    .app-name, .description { overflow-wrap: anywhere; }
                    h1 { margin: 0; font-size: 24px; line-height: 1.3; letter-spacing: -.02em; }
                    .app-name { margin: 8px 0 0; color: #0756bc; font-size: 16px; font-weight: 700; }
                    .description { max-width: 390px; margin: 12px auto 0; color: #62748c; font-size: 14px; line-height: 1.65; }
                    .content { padding: 24px 32px 30px; }
                    .meta { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 13px 15px; border: 1px solid #e5edf6; border-radius: 13px; background: #f8fbff; font-size: 13px; }
                    .meta-label { color: #75869c; }
                    .meta-value { max-width: 65%%; overflow: hidden; color: #27415f; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
                    .section-title { margin: 25px 0 12px; color: #314a68; font-size: 14px; font-weight: 700; }
                    .scopes { display: grid; gap: 8px; padding: 0; margin: 0; list-style: none; }
                    .scopes li { display: flex; align-items: center; gap: 10px; min-height: 38px; padding: 8px 11px; color: #3d526d; border-radius: 10px; background: #f7faff; font-size: 14px; }
                    .scope-dot { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%%; background: #0b73e0; box-shadow: 0 0 0 4px #dcebfb; }
                    .notice { margin: 20px 0 0; color: #71839a; font-size: 12px; line-height: 1.6; }
                    form { display: flex; gap: 10px; margin-top: 25px; }
                    button { flex: 1; min-height: 44px; padding: 10px 18px; border: 1px solid #c8d7e8; border-radius: 11px; color: #34506f; background: #fff; font: inherit; font-size: 14px; font-weight: 700; cursor: pointer; transition: border-color .16s ease, background-color .16s ease, box-shadow .16s ease, transform .16s ease; }
                    button:hover { border-color: #9ab8d8; background: #f5f9fe; }
                    button:active { transform: translateY(1px); }
                    button:focus-visible { outline: 3px solid rgb(11 115 224 / 30%%); outline-offset: 2px; }
                    button[value="allow"] { border-color: #0b73e0; color: #fff; background: linear-gradient(135deg, #0b87fd, #0756bc); box-shadow: 0 8px 16px rgb(11 115 224 / 22%%); }
                    button[value="allow"]:hover { border-color: #0756bc; background: linear-gradient(135deg, #0879e5, #064da8); }
                    @media (max-width: 480px) { body { padding: 16px 12px; } .hero, .content { padding-left: 20px; padding-right: 20px; } .meta { align-items: flex-start; flex-direction: column; gap: 4px; } .meta-value { max-width: 100%%; } }
                    @media (prefers-reduced-motion: reduce) { button { transition: none; } }
                  </style>
                </head>
                <body>
                  <div class="shell">
                    <main>
                      <div class="hero">
                        <div class="app-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a7 7 0 0 0-7 7v2H3.8a1.8 1.8 0 0 0-1.8 1.8v7.4A1.8 1.8 0 0 0 3.8 22h16.4a1.8 1.8 0 0 0 1.8-1.8v-7.4a1.8 1.8 0 0 0-1.8-1.8H19V9a7 7 0 0 0-7-7Zm-4 7a4 4 0 0 1 8 0v2H8V9Zm4 5a2 2 0 0 1 1 3.73V19h-2v-1.27A2 2 0 0 1 12 14Z"/></svg></div>
                        <h1>确认应用授权</h1>
                        <div class="app-name">%1$s</div>
                        <p class="description">%2$s</p>
                      </div>
                      <div class="content">
                        <div class="meta"><span class="meta-label">授权账户</span><span class="meta-value">%3$s</span></div>
                        <div class="meta" style="margin-top:8px"><span class="meta-label">回调地址</span><span class="meta-value" title="%4$s">%4$s</span></div>
                        <div class="section-title">此应用将获得以下权限</div>
                        <ul class="scopes">%5$s</ul>
                        <p class="notice">授权后，你可以在个人中心的“应用授权”中随时撤销访问权限。</p>
                        <form method="post" action="/oidc/authorize">
                          <input type="hidden" name="%6$s" value="%7$s">
                          <input type="hidden" name="request_id" value="%8$s">
                          <button type="submit" name="decision" value="deny">拒绝</button>
                          <button type="submit" name="decision" value="allow">同意并继续</button>
                        </form>
                      </div>
                    </main>
                  </div>
                </body>
                </html>
                """;
}
