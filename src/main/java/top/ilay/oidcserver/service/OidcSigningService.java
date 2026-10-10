package top.ilay.oidcserver.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import run.halo.app.core.extension.User;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.Secret;
import top.ilay.oidcserver.config.OidcSettings;
import top.ilay.oidcserver.util.ExtensionUtils;
import top.ilay.oidcserver.util.OidcCrypto;

@Service
@RequiredArgsConstructor
public class OidcSigningService {
    private static final String KEY_NAME = "oidc-server-signing-key";
    private final ReactiveExtensionClient store;
    private final OidcSettings settings;
    private final Clock clock;

    private Mono<RSAKey> key() {
        return store.fetch(Secret.class, KEY_NAME).filter(ExtensionUtils::active).flatMap(this::parseKey)
            .switchIfEmpty(Mono.defer(() ->
                Mono.fromCallable(() -> new RSAKeyGenerator(2048).keyID(OidcCrypto.random()).generate())
                    .subscribeOn(Schedulers.boundedElastic()).flatMap(key -> {
                        var secret = OidcCrypto.named(new Secret(), KEY_NAME); secret.setType(Secret.SECRET_TYPE_OPAQUE);
                        secret.setData(Map.of("jwk", key.toJSONString().getBytes(StandardCharsets.UTF_8)));
                        return store.create(secret).map(ignored -> key)
                            .onErrorResume(error -> store.fetch(Secret.class, KEY_NAME)
                                .filter(ExtensionUtils::active).flatMap(this::parseKey)
                                .switchIfEmpty(Mono.error(error)));
                    })));
    }
    private Mono<RSAKey> parseKey(Secret secret) {
        return Mono.fromCallable(() -> {
            if (secret.getData() == null || !secret.getData().containsKey("jwk")) {
                throw new IllegalStateException("OIDC 签名密钥缺失，拒绝签发");
            }
            var key = RSAKey.parse(new String(secret.getData().get("jwk"), StandardCharsets.UTF_8));
            if (!key.isPrivate() || key.size() < 2048 || key.getKeyID() == null || key.getKeyType() == null) {
                throw new IllegalStateException("OIDC 签名密钥无效");
            }
            return key;
        }).subscribeOn(Schedulers.boundedElastic());
    }
    public Mono<Map<String, Object>> jwks() {
        return key().map(key -> Map.of("keys", List.of(key.toPublicJWK().toJSONObject())));
    }
    public Mono<String> sign(User user, List<String> scopes, String clientId, String nonce, String accessToken, int lifetime) {
        var issuer = settings.issuer();
        return key().flatMap(key -> Mono.fromCallable(() -> {
            var now = clock.instant();
            var builder = new JWTClaimsSet.Builder().issuer(issuer).subject(OidcIdentityService.subject(user))
                .audience(clientId).issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(lifetime)))
                .claim("at_hash", OidcCrypto.atHash(accessToken));
            if (nonce != null) { builder.claim("nonce", nonce); }
            OidcIdentityService.claims(user, scopes).forEach(builder::claim);
            var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(key.getKeyID()).build(), builder.build());
            token.sign(new RSASSASigner(key)); return token.serialize();
        }).subscribeOn(Schedulers.boundedElastic()).timeout(Duration.ofSeconds(10)));
    }
}
