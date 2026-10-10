<script setup lang="ts">
import { ref } from 'vue'
import { VButton, VModal, VTag } from '@halo-dev/components'
import type { OidcClientResponse } from '@/api/generated'
import { copyText } from '@/utils/clipboard'

defineProps<{ client: OidcClientResponse; created?: boolean }>()
const emit = defineEmits<{ close: []; reset: [client: OidcClientResponse] }>()
const modal = ref<InstanceType<typeof VModal>>()
</script>

<template>
  <VModal
    ref="modal"
    class="oidc-credentials-modal"
    :title="created ? '应用已创建' : '应用接入信息'"
    :width="600"
    :layer-closable="false"
    @close="emit('close')"
  >
    <div class="mb-4 flex flex-wrap items-center gap-2">
      <h2 class="text-sm font-medium text-gray-900">{{ client.displayName }}</h2>
      <VTag>{{ client.clientType === 'CONFIDENTIAL' ? '机密客户端' : '公开客户端' }}</VTag>
    </div>
    <p v-if="client.clientSecret" class="oidc-credentials-notice">
      Client Secret 仅显示这一次，请现在复制并保存到应用的秘密配置中。关闭后无法再次查看。
    </p>
    <p v-else-if="client.clientType === 'PUBLIC'" class="oidc-credentials-notice">
      公开客户端使用 Client ID 与 PKCE，不需要 Client Secret。若接入服务要求密钥，请创建
      机密客户端应用。
    </p>
    <div class="space-y-5">
      <div>
        <div class="mb-2 flex items-center justify-between gap-3">
          <span class="text-sm font-medium">Client ID</span>
          <VButton size="sm" @click="copyText(client.clientId!)">复制 Client ID</VButton>
        </div>
        <code class="block select-all break-all rounded bg-gray-100 p-3 text-sm">{{
          client.clientId
        }}</code>
      </div>
      <div v-if="client.clientType === 'CONFIDENTIAL'">
        <div class="mb-2 flex items-center justify-between gap-3">
          <span class="text-sm font-medium">Client Secret</span>
          <VButton v-if="client.clientSecret" size="sm" @click="copyText(client.clientSecret)">
            复制 Client Secret
          </VButton>
        </div>
        <code
          v-if="client.clientSecret"
          data-testid="client-secret"
          class="block select-all break-all rounded bg-gray-100 p-3 text-sm"
          >{{ client.clientSecret }}</code
        >
        <div v-else class="space-y-3 rounded bg-gray-50 p-3 text-sm text-gray-600">
          <p>密钥仅在创建或重置时显示。丢失后可重置，旧密钥和令牌会立即失效。</p>
          <VButton size="sm" @click="emit('reset', client)">重置密钥</VButton>
        </div>
      </div>
      <div>
        <div class="mb-2 text-sm font-medium">回调地址</div>
        <div class="space-y-2">
          <code
            v-for="uri in client.redirectUris"
            :key="uri"
            class="block select-all break-all rounded bg-gray-50 p-3 text-sm"
            >{{ uri }}</code
          >
        </div>
      </div>
      <div>
        <div class="mb-2 text-sm font-medium">允许的 Scope</div>
        <div class="flex flex-wrap gap-2">
          <VTag v-for="scope in client.scopes" :key="scope">{{ scope }}</VTag>
        </div>
      </div>
    </div>
    <template #footer>
      <div class="flex justify-end">
        <VButton type="secondary" @click="modal?.close()">
          {{ client.clientSecret ? '已保存，关闭' : '关闭' }}
        </VButton>
      </div>
    </template>
  </VModal>
</template>

<style>
.oidc-credentials-modal .modal-header,
.oidc-credentials-modal .modal-footer {
  flex-shrink: 0;
}

.oidc-credentials-modal .modal-body {
  min-height: 0;
}

.oidc-credentials-notice {
  margin-bottom: 20px;
  border-radius: 4px;
  background: #eff6ff;
  padding: 12px;
  color: #1e40af;
  font-size: 13px;
  line-height: 1.6;
}
</style>
