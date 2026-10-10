<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  Dialog,
  IconPlug,
  Toast,
  VButton,
  VCard,
  VEmpty,
  VEntity,
  VEntityContainer,
  VDropdownItem,
  VLoading,
  VPageHeader,
  VPagination,
  VStatusDot,
  VTag,
} from '@halo-dev/components'
import { consoleApi } from '@/api'
import type { OidcClientPage, OidcClientResponse } from '@/api/generated'
import ClientForm from '@/components/ClientForm.vue'
import ClientSecret from '@/components/ClientSecret.vue'
import { copyText } from '@/utils/clipboard'

const page = ref(1)
const size = ref(20)
const keyword = ref('')
const loading = ref(true)
const result = ref<OidcClientPage>()
const loadError = ref(false)
const editing = ref<OidcClientResponse>()
const creating = ref(false)
const credentials = ref<OidcClientResponse>()
const justCreated = ref(false)
const busyClient = ref<string>()
const items = computed(() => result.value?.items ?? [])
const issuer = ref('')
const oidcEndpoints = computed(() => {
  const base = issuer.value || `${window.location.origin}/oidc`
  return [
    { label: 'Issuer URL', path: `${base}` },
    { label: 'Discovery', path: `${base}/.well-known/openid-configuration` },
    { label: 'JWKS', path: `${base}/jwks` },
    { label: 'Authorization', path: `${base}/authorize` },
    { label: 'Token', path: `${base}/token` },
    { label: 'UserInfo', path: `${base}/userinfo` },
  ]
})
let fetchVersion = 0

async function loadIssuer() {
  try {
    const response = await fetch('/oidc/.well-known/openid-configuration', {
      headers: { Accept: 'application/json' },
    })
    if (response.ok) {
      const data = (await response.json()) as { issuer?: string }
      if (data.issuer) issuer.value = data.issuer.replace(/\/+$/, '')
    }
  } catch {
    // Discovery 不可用时使用当前站点地址作为展示兜底，服务端仍以固定外部地址为准。
  }
}

function handleSearch() {
  page.value = 1
  void refresh()
}
function clearSearch() {
  keyword.value = ''
  handleSearch()
}

function closeForm() {
  creating.value = false
  editing.value = undefined
}

async function refresh() {
  const version = ++fetchVersion
  loading.value = true
  try {
    const { data } = await consoleApi.listOidcClients({
      page: page.value,
      size: size.value,
      keyword: keyword.value || undefined,
    })
    if (version === fetchVersion) {
      result.value = data
      loadError.value = false
    }
  } catch {
    if (version === fetchVersion) loadError.value = true
  } finally {
    if (version === fetchVersion) loading.value = false
  }
}
function save(data: OidcClientResponse) {
  const wasCreating = creating.value
  closeForm()
  if (wasCreating) {
    justCreated.value = true
    credentials.value = data
    page.value = 1
    keyword.value = ''
  }
  void refresh()
}
function showCredentials(client: OidcClientResponse) {
  justCreated.value = false
  credentials.value = client
}
function confirmDelete(client: OidcClientResponse) {
  Dialog.warning({
    title: '删除应用',
    description: `确认删除“${client.displayName}”？其授权和令牌会立即失效。`,
    confirmText: '删除',
    cancelText: '取消',
    confirmType: 'danger',
    onConfirm: async () => {
      try {
        await consoleApi.deleteOidcClient({ name: client.name! })
        Toast.success('应用已删除')
        await refresh()
      } catch {
        Toast.error('删除失败')
      }
    },
  })
}
async function toggle(client: OidcClientResponse) {
  if (busyClient.value) return
  busyClient.value = client.name
  try {
    await (client.enabled
      ? consoleApi.disableOidcClient({ name: client.name! })
      : consoleApi.enableOidcClient({ name: client.name! }))
    await refresh()
  } catch {
    Toast.error('更新状态失败')
  } finally {
    busyClient.value = undefined
  }
}
function resetSecret(client: OidcClientResponse) {
  Dialog.warning({
    title: '重置客户端密钥',
    description: '重置后旧密钥和旧令牌立即失效，确认继续？',
    confirmText: '重置',
    cancelText: '取消',
    confirmType: 'danger',
    onConfirm: async () => {
      try {
        const { data } = await consoleApi.resetOidcClientSecret({ name: client.name! })
        showCredentials(data)
        Toast.success('客户端密钥已重置')
        await refresh()
      } catch {
        Toast.error('重置失败')
      }
    },
  })
}
onMounted(() => {
  void loadIssuer()
  void refresh()
})
</script>

<template>
  <VPageHeader title="OIDC 应用">
    <template #icon><IconPlug /></template>
    <template #actions>
      <VButton type="secondary" @click="creating = true">创建应用</VButton>
    </template>
  </VPageHeader>
  <div class="oidc-apps-page m-0 space-y-4 md:m-4">
    <VCard :body-class="['!p-0']">
      <template #header>
        <div class="oidc-apps-toolbar">
          <div>
            <h2 class="text-sm font-medium text-gray-900">已注册应用</h2>
            <p class="mt-1 text-xs text-gray-500">
              共 {{ result?.total ?? 0 }} 个应用，查看接入凭据并管理访问权限。
            </p>
          </div>
          <div class="oidc-apps-search">
            <SearchInput
              v-model="keyword"
              placeholder="按应用名称搜索"
              @update:model-value="handleSearch"
            />
            <VButton size="sm" :loading="loading" @click="refresh">刷新</VButton>
          </div>
        </div>
      </template>
      <VLoading v-if="loading" />
      <div v-else-if="loadError" role="alert" class="p-8 text-center text-sm text-gray-600">
        <p class="mb-4">无法加载应用，请检查登录状态和管理权限后重试。</p>
        <VButton @click="refresh">重新加载</VButton>
      </div>
      <VEmpty
        v-else-if="!items.length"
        :title="keyword ? '没有匹配的应用' : '还没有 OIDC 应用'"
        :message="
          keyword
            ? '试试其他名称，或清空搜索查看全部应用。'
            : '创建应用后获取 Client ID 和接入凭据，使用 Halo 账户登录。'
        "
      >
        <template #actions>
          <VButton v-if="keyword" @click="clearSearch">清空搜索</VButton>
          <VButton v-else type="secondary" @click="creating = true">创建第一个应用</VButton>
        </template>
      </VEmpty>
      <div v-else class="oidc-entity-list">
        <VEntityContainer>
          <VEntity v-for="client in items" :key="client.name">
            <template #start>
              <div class="oidc-app-summary">
                <button class="oidc-app-name" @click="showCredentials(client)">
                  {{ client.displayName }}
                </button>
                <div class="oidc-app-labels">
                  <VTag>{{
                    client.clientType === 'CONFIDENTIAL' ? '机密客户端' : '公开客户端'
                  }}</VTag>
                  <span class="text-xs text-gray-500">
                    {{
                      client.accessPolicy === 'ROLES'
                        ? `指定角色（${client.roles?.length ?? 0}）`
                        : '所有已登录用户'
                    }}
                  </span>
                </div>
                <p
                  v-if="client.description"
                  class="oidc-app-description"
                  :title="client.description"
                >
                  {{ client.description }}
                </p>
              </div>
              <div class="oidc-app-identifiers">
                <div class="oidc-app-client-id">
                  <span class="text-xs text-gray-500">Client ID</span>
                  <code class="select-all text-xs text-gray-700">{{ client.clientId }}</code>
                  <VButton size="sm" @click="copyText(client.clientId!)">复制</VButton>
                </div>
                <p class="oidc-app-callback" :title="client.redirectUris?.join('\n')">
                  <span class="text-gray-400">回调</span> {{ client.redirectUris?.[0] }}
                  <span v-if="(client.redirectUris?.length ?? 0) > 1">
                    （共 {{ client.redirectUris?.length }} 个）
                  </span>
                </p>
              </div>
            </template>
            <template #end>
              <VStatusDot
                :state="client.enabled ? 'success' : 'default'"
                :text="client.enabled ? '已启用' : '已停用'"
              />
              <VButton size="sm" @click="showCredentials(client)">接入信息</VButton>
              <VButton size="sm" @click="editing = client">编辑</VButton>
            </template>
            <template #dropdownItems>
              <VDropdownItem :disabled="!!busyClient" @click="toggle(client)">
                {{ client.enabled ? '停用应用' : '启用应用' }}
              </VDropdownItem>
              <VDropdownItem
                v-if="client.clientType === 'CONFIDENTIAL'"
                @click="resetSecret(client)"
                >重置密钥</VDropdownItem
              >
              <VDropdownItem type="danger" @click="confirmDelete(client)">删除应用</VDropdownItem>
            </template>
          </VEntity>
        </VEntityContainer>
      </div>
      <VPagination
        v-if="(result?.total ?? 0) > 0"
        v-model:page="page"
        v-model:size="size"
        :total="result?.total ?? 0"
        @change="refresh"
      />
    </VCard>
    <VCard class="oidc-endpoints-card">
      <template #header>
        <div class="oidc-endpoints-heading">
          <div>
            <h2 class="text-sm font-medium text-gray-900">OIDC 服务端点</h2>
            <p class="mt-1 text-xs text-gray-500">
              第三方应用可通过 Discovery 自动读取以下地址；服务开关见插件详情 → 设置。
            </p>
          </div>
        </div>
      </template>
      <div class="oidc-endpoint-grid">
        <div v-for="endpoint in oidcEndpoints" :key="endpoint.label" class="oidc-endpoint-row">
          <span class="oidc-endpoint-label">{{ endpoint.label }}</span>
          <a
            v-if="endpoint.label !== 'Issuer URL'"
            :href="endpoint.path"
            target="_blank"
            rel="noreferrer"
            class="oidc-endpoint-url"
            >{{ endpoint.path }}</a
          >
          <span v-else class="oidc-endpoint-url">{{ endpoint.path }}</span>
          <VButton size="sm" @click="copyText(endpoint.path)">复制</VButton>
        </div>
      </div>
    </VCard>
  </div>
  <ClientForm v-if="creating || editing" :client="editing" @close="closeForm" @saved="save" />
  <ClientSecret
    v-if="credentials"
    :client="credentials"
    :created="justCreated"
    @close="credentials = undefined"
    @reset="resetSecret"
  />
</template>

<style>
.oidc-apps-toolbar {
  display: flex;
  width: 100%;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 20px;
}

.oidc-apps-toolbar h2,
.oidc-endpoints-heading h2 {
  letter-spacing: -0.01em;
}

.oidc-entity-list {
  overflow-x: auto;
}

.oidc-entity-list table {
  table-layout: fixed;
}

.oidc-entity-list .entity-body {
  min-height: 92px;
}

.oidc-entity-list .entity-wrapper {
  border-bottom: 1px solid #eef2f7;
}

.oidc-entity-list .entity-wrapper:last-child {
  border-bottom: 0;
}

.oidc-entity-list .entity-start-wrapper {
  width: calc(100% - 350px);
}

.oidc-entity-list .entity-end-wrapper {
  width: 350px;
}

.oidc-endpoints-card .card-header {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
  padding: 18px 20px;
}

.oidc-endpoints-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.oidc-endpoint-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 12px;
  padding: 16px 20px 20px;
}

.oidc-endpoint-row {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  border-radius: 6px;
  border: 1px solid #e5e7eb;
  background: #fbfdff;
  padding: 9px 10px;
  transition:
    border-color 0.15s ease,
    background-color 0.15s ease;
}

.oidc-endpoint-row:hover {
  border-color: #bfdbfe;
  background: #f8fbff;
}

.oidc-endpoint-label {
  flex: 0 0 92px;
  color: #475569;
  font-size: 12px;
  font-weight: 500;
}

.oidc-endpoint-url {
  min-width: 0;
  flex: 1;
  overflow: hidden;
  color: #2563eb;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.oidc-endpoint-url:hover {
  text-decoration: underline;
}

.oidc-apps-search {
  display: flex;
  align-items: center;
  gap: 12px;
}

.oidc-apps-page .entity-start {
  min-width: 0;
  gap: 32px;
  width: 100%;
}

.oidc-apps-page .entity-end {
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-start;
}

.oidc-app-summary {
  min-width: 0;
  flex: 0 0 240px;
}

.oidc-app-identifiers {
  min-width: 0;
  flex: 1;
}

.oidc-apps-page .pagination {
  border-top: 1px solid #e5e7eb;
  padding: 10px 20px;
}

.oidc-app-name {
  display: block;
  max-width: 100%;
  overflow: hidden;
  color: #111827;
  font-size: 14px;
  font-weight: 500;
  text-align: left;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.oidc-app-name:hover {
  color: #2563eb;
}

.oidc-app-labels {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}

.oidc-app-description {
  overflow: hidden;
  margin-top: 8px;
  color: #6b7280;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.oidc-app-identifiers {
  min-width: 0;
}

.oidc-app-client-id {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.oidc-app-client-id span {
  flex-shrink: 0;
}

.oidc-app-client-id code {
  overflow-wrap: anywhere;
}

.oidc-app-callback {
  overflow: hidden;
  max-width: 440px;
  margin-top: 8px;
  color: #6b7280;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 1279px) {
  .oidc-entity-list .entity-start-wrapper,
  .oidc-entity-list .entity-end-wrapper {
    width: auto;
  }

  .oidc-apps-page .entity-start {
    align-items: flex-start;
    flex-direction: column;
    gap: 12px;
  }

  .oidc-entity-list .entity-body {
    min-height: 0;
  }

  .oidc-app-summary {
    flex-basis: auto;
  }

  .oidc-app-identifiers {
    width: 100%;
  }
}

@media (max-width: 767px) {
  .oidc-endpoint-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .oidc-endpoints-heading {
    align-items: flex-start;
    flex-direction: column;
    gap: 8px;
  }

  .oidc-apps-search {
    width: 100%;
    justify-content: space-between;
  }

  .oidc-apps-page .entity-wrapper,
  .oidc-apps-page .entity-start-wrapper,
  .oidc-apps-page .entity-end-wrapper {
    display: block;
  }

  .oidc-apps-page .entity-start-wrapper {
    padding-bottom: 8px;
  }

  .oidc-apps-page .entity-end {
    flex-wrap: wrap;
    justify-content: flex-start;
  }

  .oidc-app-callback {
    max-width: calc(100vw - 48px);
  }
}
</style>
