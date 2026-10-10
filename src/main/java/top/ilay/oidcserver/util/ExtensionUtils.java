package top.ilay.oidcserver.util;

import run.halo.app.extension.Extension;

/** 扩展资源的公共状态判断，供业务服务和清理控制器使用。 */
public final class ExtensionUtils {
    private ExtensionUtils() {
    }

    public static boolean active(Extension value) {
        return value != null && value.getMetadata() != null
            && value.getMetadata().getDeletionTimestamp() == null;
    }
}
