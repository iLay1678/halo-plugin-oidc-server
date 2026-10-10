<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Dialog, Toast, VButton, VEmpty, VLoading } from '@halo-dev/components'
import { userApi } from '@/api'
import type { OidcConsentResponse } from '@/api/generated'
import { describeScopes } from '@/utils/scopes'
const items = ref<OidcConsentResponse[]>([])
const loading = ref(true)
async function refresh() {
  loading.value = true
  try {
    const { data } = await userApi.listMyOidcAuthorizations({ page: 1, size: 100 })
    items.value = data.items ?? []
  } catch {
    Toast.error('无法加载授权列表')
  } finally {
    loading.value = false
  }
}
function revoke(item: OidcConsentResponse) {
  Dialog.warning({
    title: '撤销授权',
    description: `撤销“${item.displayName}”后，该应用的令牌会立即失效。`,
    confirmText: '撤销',
    cancelText: '取消',
    confirmType: 'danger',
    onConfirm: async () => {
      try {
        await userApi.revokeMyOidcAuthorization({ name: item.name! })
        Toast.success('授权已撤销')
        await refresh()
      } catch {
        Toast.error('撤销失败')
      }
    },
  })
}
onMounted(refresh)
</script>
<template>
  <div class="p-4">
    <h2 class="mb-4 text-base font-medium">已授权的应用</h2>
    <VLoading v-if="loading" /><VEmpty
      v-else-if="!items.length"
      title="暂无应用授权"
      message="使用 OIDC 应用登录后，授权记录会显示在这里。"
    />
    <div v-else class="divide-y rounded border">
      <div
        v-for="item in items"
        :key="item.name"
        class="flex items-center justify-between gap-4 p-4"
      >
        <div>
          <p class="font-medium">{{ item.displayName }}</p>
          <p class="text-xs text-gray-500">
            {{ describeScopes(item.scopes) }} ·
            {{ item.grantedAt ? new Date(item.grantedAt).toLocaleString() : '' }}
          </p>
        </div>
        <VButton v-if="!item.revoked" size="sm" type="secondary" @click="revoke(item)"
          >撤销授权</VButton
        ><span v-else class="text-sm text-gray-400">已撤销</span>
      </div>
    </div>
  </div>
</template>
