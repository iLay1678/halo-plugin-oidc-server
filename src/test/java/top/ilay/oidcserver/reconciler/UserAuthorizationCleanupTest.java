package top.ilay.oidcserver.reconciler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.AdditionalAnswers.delegatesTo;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.test.StepVerifier;
import run.halo.app.core.extension.User;
import run.halo.app.extension.ExtensionClient;
import run.halo.app.extension.ExtensionUtil;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.PageRequestImpl;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.controller.Reconciler.Request;
import org.springframework.data.domain.Sort;
import top.ilay.oidcserver.extension.OidcAuthorizationCode;
import top.ilay.oidcserver.extension.OidcConsent;
import top.ilay.oidcserver.extension.OidcToken;
import top.ilay.oidcserver.extension.OidcTokenFamily;
import top.ilay.oidcserver.protocol.OAuthError;
import top.ilay.oidcserver.service.OidcIdentityService;
import top.ilay.oidcserver.service.OidcConsentService;
import top.ilay.oidcserver.support.OidcTestFixture;
import top.ilay.oidcserver.util.OidcCrypto;
import top.ilay.oidcserver.web.OidcUserEndpoint;

class UserAuthorizationCleanupTest extends OidcTestFixture {
    @Test
    void deletionWaitsForAllRecordsBeforeAllowingSameNameAndOldTokensStayInvalid() {
        var verifier = OidcCrypto.random();
        var request = request(verifier);
        var code = tokens.authorize(request, app, consent).block(WAIT);
        var issued = tokens.exchange(app, code, request.redirectUri(), verifier).block(WAIT);
        var unusedCode = tokens.authorize(request, app, consent).block(WAIT);
        var bob = OidcCrypto.named(new User(), "bob"); bob.setSpec(new User.UserSpec()); bob = store.add(bob);
        var other = consents.grant(bob, app, List.of("openid")).block(WAIT);
        api().get().uri("/authorizations?page=1&size=1").exchange().expectStatus().isOk()
            .expectBody().jsonPath("$.total").isEqualTo(1).jsonPath("$.items[0].name").isEqualTo(consent.getMetadata().getName());

        var cleanup = new UserAuthorizationCleanup(store.synchronous);
        store.delete(store.snapshot(User.class, "alice"));
        assertThat(cleanup.reconcile(new Request("alice")).reEnqueue()).isTrue();
        assertThat(store.snapshot(User.class, "alice").getMetadata().getFinalizers())
            .contains(OidcIdentityService.USER_FINALIZER);
        assertThatThrownBy(() -> store.add(newAlice())).isInstanceOf(OptimisticLockingFailureException.class);
        // 再次调谐时即使全部已标记删除，也必须等待 GC。
        assertThat(cleanup.reconcile(new Request("alice")).reEnqueue()).isTrue();
        store.collectGarbage();
        assertThat(store.snapshot(User.class, "alice")).isNotNull();
        assertThat(cleanup.reconcile(new Request("alice")).reEnqueue()).isFalse();
        store.collectGarbage();
        assertThat(store.snapshot(User.class, "alice")).isNull();
        for (var type : List.of(OidcConsent.class, OidcAuthorizationCode.class, OidcToken.class, OidcTokenFamily.class)) {
            var remaining = store.synchronous.listBy(type, new ListOptions(), PageRequestImpl.of(1, 100, Sort.unsorted()));
            assertThat(remaining.getItems()).allMatch(value -> value.getMetadata().getName().equals(other.getMetadata().getName()));
        }

        var replacement = store.add(newAlice());
        assertThat(OidcIdentityService.subject(replacement)).isNotEqualTo(OidcIdentityService.subject(user));
        api().get().uri("/authorizations").exchange().expectStatus().isOk()
            .expectBody().jsonPath("$.total").isEqualTo(0).jsonPath("$.items").isEmpty();
        api().post().uri("/authorizations/{name}/revoke", consent.getMetadata().getName()).exchange().expectStatus().isNotFound();
        StepVerifier.create(tokens.userinfo((String) issued.get("access_token"))).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(tokens.refresh(app, (String) issued.get("refresh_token"), null)).expectError(OAuthError.class).verify(WAIT);
        StepVerifier.create(tokens.exchange(app, unusedCode, request.redirectUri(), verifier)).expectError(OAuthError.class).verify(WAIT);
        var fresh = consents.grant(replacement, app, List.of("openid")).block(WAIT);
        api().get().uri("/authorizations").exchange().expectStatus().isOk()
            .expectBody().jsonPath("$.total").isEqualTo(1).jsonPath("$.items[0].name").isEqualTo(fresh.getMetadata().getName());
        api().post().uri("/authorizations/{name}/revoke", fresh.getMetadata().getName()).exchange().expectStatus().isOk();
    }

    @Test
    void orphanedLegacyRecordsAreHiddenAndCannotBeOverwrittenOrRevokedByReplacement() {
        var legacy = store.snapshot(OidcConsent.class, consent.getMetadata().getName());
        store.delete(legacy); store.collectGarbage();
        legacy.getMetadata().setName("consent-" + OidcCrypto.digest("alice\0" + app.getMetadata().getName()));
        legacy.getMetadata().setVersion(null); legacy = store.add(legacy);
        // 模拟旧版本或插件停用期间删除账户，旧授权尚未清理。
        new UserAuthorizationCleanup(store.synchronous).releaseFinalizers();
        store.delete(store.snapshot(User.class, "alice")); store.collectGarbage();
        var replacement = store.add(newAlice());
        var legacyName = legacy.getMetadata().getName();
        api().get().uri("/authorizations?page=1&size=1").exchange().expectStatus().isOk()
            .expectBody().jsonPath("$.total").isEqualTo(0).jsonPath("$.items").isEmpty();
        api().post().uri("/authorizations/{name}/revoke", legacyName).exchange().expectStatus().isNotFound();
        assertThat(store.snapshot(OidcConsent.class, legacyName).getSpec().isRevoked()).isFalse();
        StepVerifier.create(consents.reusable(replacement, app, List.of("openid"))).verifyComplete();
        StepVerifier.create(consents.grant(user, app, List.of("openid"))).expectError(OAuthError.class).verify(WAIT);
        var fresh = consents.grant(replacement, app, List.of("openid")).block(WAIT);
        assertThat(fresh.getMetadata().getName()).isNotEqualTo(legacyName);
        assertThat(store.snapshot(OidcConsent.class, legacyName).getSpec().getSubject()).isEqualTo(legacy.getSpec().getSubject());
        api().get().uri("/authorizations?page=1&size=1").exchange().expectStatus().isOk()
            .expectBody().jsonPath("$.total").isEqualTo(1).jsonPath("$.items[0].name").isEqualTo(fresh.getMetadata().getName());
        var cleanup = new ConsentCleanup(store.synchronous);
        cleanup.reconcile(new Request(legacyName));
        cleanup.reconcile(new Request(fresh.getMetadata().getName()));
        store.collectGarbage();
        assertThat(store.snapshot(OidcConsent.class, legacyName)).isNull();
        assertThat(store.snapshot(OidcConsent.class, fresh.getMetadata().getName())).isNotNull();
    }

    @Test
    void deletionFailureKeepsUserProtectionAndRetryCompletesCleanup() {
        store.delete(store.snapshot(User.class, "alice"));
        var faulty = mock(ExtensionClient.class, delegatesTo(store.synchronous));
        doAnswer(invocation -> { throw new IllegalStateException("模拟存储故障"); }).when(faulty).delete(any());
        assertThatThrownBy(() -> new UserAuthorizationCleanup(faulty).reconcile(new Request("alice")))
            .isInstanceOf(IllegalStateException.class);
        store.collectGarbage();
        assertThat(store.snapshot(User.class, "alice").getMetadata().getFinalizers()).contains(OidcIdentityService.USER_FINALIZER);
        var cleanup = new UserAuthorizationCleanup(store.synchronous);
        cleanup.reconcile(new Request("alice")); store.collectGarbage();
        cleanup.reconcile(new Request("alice")); store.collectGarbage();
        assertThat(store.snapshot(User.class, "alice")).isNull();
    }

    @Test
    void deletionDuringGrantDoesNotReturnOrLeaveAnActiveConsent() {
        var racing = mock(ReactiveExtensionClient.class, delegatesTo(store.client));
        doAnswer(invocation -> store.client.update((OidcConsent) invocation.getArgument(0)).doOnNext(saved ->
            store.delete(store.snapshot(User.class, "alice")))).when(racing).update(any(OidcConsent.class));
        var service = new OidcConsentService(racing, clients, identity, clock);
        StepVerifier.create(service.grant(user, app, List.of("openid"))).expectError(OAuthError.class).verify(WAIT);
        assertThat(store.snapshot(OidcConsent.class, consent.getMetadata().getName()).getMetadata().getDeletionTimestamp()).isNotNull();
        var cleanup = new UserAuthorizationCleanup(store.synchronous);
        cleanup.reconcile(new Request("alice")); store.collectGarbage();
        cleanup.reconcile(new Request("alice")); store.collectGarbage();
        assertThat(store.snapshot(User.class, "alice")).isNull();
        assertThat(store.snapshot(OidcConsent.class, consent.getMetadata().getName())).isNull();
    }

    @Test
    void originalAccountCanReuseAndRevokeLegacyNamedConsent() {
        var legacy = store.snapshot(OidcConsent.class, consent.getMetadata().getName());
        store.delete(legacy); store.collectGarbage();
        legacy.getMetadata().setName("consent-" + OidcCrypto.digest("alice\0" + app.getMetadata().getName()));
        legacy.getMetadata().setVersion(null); legacy = store.add(legacy);
        var reusable = consents.reusable(user, app, List.of("openid")).block(WAIT);
        assertThat(reusable.getMetadata().getName()).isEqualTo(legacy.getMetadata().getName());
        var renewed = consents.grant(user, app, List.of("openid")).block(WAIT);
        assertThat(renewed.getMetadata().getName()).isEqualTo(legacy.getMetadata().getName());
        assertThat(consents.list(user, 1, 20).block(WAIT).total()).isEqualTo(1);
        assertThat(consents.revoke(legacy.getMetadata().getName(), user).block(WAIT).revoked()).isTrue();
    }

    @Test
    void batchesIncludeRevokedRecordsAndNeverReleaseProtectionEarly() {
        for (int i = 0; i < 105; i++) {
            var value = store.snapshot(OidcConsent.class, consent.getMetadata().getName());
            value.getMetadata().setName("extra-" + i); value.getMetadata().setVersion(null);
            value.getSpec().setRevoked(true); store.add(value);
        }
        store.delete(store.snapshot(User.class, "alice"));
        var cleanup = new UserAuthorizationCleanup(store.synchronous);
        assertThat(cleanup.reconcile(new Request("alice")).reEnqueue()).isTrue(); store.collectGarbage();
        assertThat(cleanup.reconcile(new Request("alice")).reEnqueue()).isTrue(); store.collectGarbage();
        assertThat(cleanup.reconcile(new Request("alice")).reEnqueue()).isFalse(); store.collectGarbage();
        assertThat(store.snapshot(User.class, "alice")).isNull();
    }

    @Test
    void finalizersAreAddedBeforeCreationAndReleasedOnStopWithoutRemovingOthers() {
        var cleanup = new UserAuthorizationCleanup(store.synchronous);
        var newUser = newAlice(); newUser.getMetadata().setFinalizers(Set.of("other-plugin/protection"));
        cleanup.preCreating(newUser).block(WAIT);
        assertThat(newUser.getMetadata().getFinalizers()).containsExactlyInAnyOrder("other-plugin/protection", OidcIdentityService.USER_FINALIZER);
        var saved = store.snapshot(User.class, "alice");
        ExtensionUtil.addFinalizers(saved.getMetadata(), Set.of("other-plugin/protection")); store.save(saved, true);
        cleanup.releaseFinalizers();
        assertThat(store.snapshot(User.class, "alice").getMetadata().getFinalizers()).containsExactly("other-plugin/protection");
        assertThat(store.snapshot(OidcConsent.class, consent.getMetadata().getName())).isNotNull();
        cleanup.reconcile(new Request("alice"));
        assertThat(store.snapshot(User.class, "alice").getMetadata().getFinalizers()).contains(OidcIdentityService.USER_FINALIZER);
    }

    @Test
    void consentCleanupHandlesMissingAndDeletingUsersButPreservesActiveOwners() {
        var cleanup = new ConsentCleanup(store.synchronous);
        cleanup.reconcile(new Request(consent.getMetadata().getName()));
        assertThat(store.snapshot(OidcConsent.class, consent.getMetadata().getName()).getMetadata().getDeletionTimestamp()).isNull();
        var orphan = store.snapshot(OidcConsent.class, consent.getMetadata().getName());
        orphan.getMetadata().setName("orphan"); orphan.getMetadata().setVersion(null); orphan.getSpec().setUsername("missing-user");
        store.add(orphan); cleanup.reconcile(new Request("orphan")); store.collectGarbage();
        assertThat(store.snapshot(OidcConsent.class, "orphan")).isNull();
        store.delete(store.snapshot(User.class, "alice"));
        cleanup.reconcile(new Request(consent.getMetadata().getName())); store.collectGarbage();
        assertThat(store.snapshot(OidcConsent.class, consent.getMetadata().getName())).isNull();
    }

    private User newAlice() {
        var replacement = OidcCrypto.named(new User(), "alice"); replacement.setSpec(new User.UserSpec());
        replacement.getMetadata().setCreationTimestamp(Instant.parse("2026-10-12T01:00:00Z"));
        return replacement;
    }

    private WebTestClient api() {
        var auth = new TestingAuthenticationToken("alice", ""); auth.setAuthenticated(true);
        return WebTestClient.bindToRouterFunction(new OidcUserEndpoint(identity, consents).endpoint())
            .webFilter((exchange, chain) -> chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
            .configureClient().responseTimeout(WAIT).build();
    }
}
