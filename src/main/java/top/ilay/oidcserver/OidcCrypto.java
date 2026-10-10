package top.ilay.oidcserver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.Metadata;

public final class OidcCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private OidcCrypto() { }
    public static String random() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    public static byte[] hash(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException("缺少 SHA-256", error); }
    }
    public static String digest(String value) { return HexFormat.of().formatHex(hash(value)); }
    public static String challenge(String verifier) { return Base64.getUrlEncoder().withoutPadding().encodeToString(hash(verifier)); }
    public static String atHash(String token) { return Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOf(hash(token), 16)); }
    public static boolean equal(String first, String second) {
        return first != null && second != null && MessageDigest.isEqual(first.getBytes(StandardCharsets.UTF_8), second.getBytes(StandardCharsets.UTF_8));
    }
    public static <E extends AbstractExtension> E named(E extension, String name) {
        var metadata = new Metadata();
        metadata.setName(name);
        extension.setMetadata(metadata);
        return extension;
    }
    public static void copy(GrantBinding from, GrantBinding to) {
        to.setClientId(from.getClientId()); to.setUsername(from.getUsername());
        to.setSubject(from.getSubject()); to.setIssuer(from.getIssuer());
        to.setClientVersion(from.getClientVersion()); to.setConsentName(from.getConsentName());
        to.setConsentVersion(from.getConsentVersion()); to.setScopes(java.util.List.copyOf(from.getScopes()));
        to.setExpiresAt(from.getExpiresAt());
    }
}
