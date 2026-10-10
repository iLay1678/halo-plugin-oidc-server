<script setup lang="ts">
import { reactive, ref } from 'vue'
import { submitForm } from '@formkit/core'
import { Toast, VButton, VModal } from '@halo-dev/components'
import { consoleApi } from '@/api'
import type { OidcClientRequest, OidcClientResponse } from '@/api/generated'
import { OidcClientRequestAccessPolicyEnum, OidcClientRequestClientTypeEnum } from '@/api/generated'
import { createRoleOptions } from '@/utils/role-options'

const props = defineProps<{ client?: OidcClientResponse }>()
const emit = defineEmits<{ close: []; saved: [result: OidcClientResponse] }>()
const modal = ref<InstanceType<typeof VModal>>()
const saving = ref(false)
const roleOptions = createRoleOptions(async (keyword) => {
  try {
    const { data } = await consoleApi.listOidcRoles({ keyword: keyword || undefined })
    return (data.items ?? []).flatMap((role) =>
      role.name
        ? [{ label: role.displayName || role.name, value: role.name, description: role.name }]
        : [],
    )
  } catch (error) {
    Toast.error('无法加载角色列表')
    throw error
  }
})
const form = reactive<
  Required<
    Pick<
      OidcClientRequest,
      'displayName' | 'description' | 'clientType' | 'accessPolicy' | 'enabled'
    >
  > & { redirectUrisText: string; scopes: string[]; roles: string[] }
>({
  displayName: props.client?.displayName ?? '',
  description: props.client?.description ?? '',
  clientType: props.client?.clientType ?? OidcClientRequestClientTypeEnum.Confidential,
  accessPolicy: props.client?.accessPolicy ?? OidcClientRequestAccessPolicyEnum.All,
  enabled: props.client?.enabled ?? true,
  redirectUrisText: (props.client?.redirectUris ?? []).join('\n'),
  scopes: [...(props.client?.scopes ?? ['openid', 'profile'])],
  roles: [...(props.client?.roles ?? [])],
})

async function submit() {
  if (saving.value) return
  const redirectUris = form.redirectUrisText
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean)
  if (!redirectUris.length) {
    Toast.error('至少填写一个回调地址')
    return
  }
  if (!form.scopes.includes('openid')) {
    Toast.error('必须允许 openid Scope')
    return
  }
  if (form.accessPolicy === OidcClientRequestAccessPolicyEnum.Roles && !form.roles.length) {
    Toast.error('按角色限制时至少选择一个角色')
    return
  }
  saving.value = true
  try {
    const request: OidcClientRequest = {
      displayName: form.displayName,
      description: form.description,
      clientType: form.clientType,
      accessPolicy: form.accessPolicy,
      enabled: form.enabled,
      redirectUris,
      roles: form.accessPolicy === 'ROLES' ? form.roles : [],
      scopes: form.scopes,
    }
    const response = props.client?.name
      ? await consoleApi.updateOidcClient({ name: props.client.name, oidcClientRequest: request })
      : await consoleApi.createOidcClient({ oidcClientRequest: request })
    Toast.success(props.client ? '应用已更新' : '应用已创建')
    emit('saved', response.data)
    modal.value?.close()
  } catch {
    Toast.error('保存失败，请检查权限和配置')
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <VModal
    ref="modal"
    class="oidc-client-modal"
    :title="client ? '编辑 OIDC 应用' : '创建 OIDC 应用'"
    :width="640"
    :body-class="['oidc-client-form-body']"
    @close="emit('close')"
  >
    <FormKit id="oidc-client-form" type="form" :actions="false" :disabled="saving" @submit="submit">
      <div class="oidc-client-form-row">
        <FormKit
          v-model="form.displayName"
          type="text"
          name="displayName"
          label="应用名称"
          placeholder="例如：RustDesk"
          validation="required"
        />
        <FormKit
          v-model="form.clientType"
          type="select"
          name="clientType"
          label="客户端类型"
          :disabled="!!client"
          :options="[
            { label: '机密客户端（服务端应用）', value: 'CONFIDENTIAL' },
            { label: '公开客户端（浏览器 / 移动端）', value: 'PUBLIC' },
          ]"
        />
      </div>
      <p class="oidc-client-type-help">
        {{
          form.clientType === 'CONFIDENTIAL'
            ? '适用于能保管密钥的服务端应用，创建后生成 Client ID 和 Client Secret。'
            : '适用于浏览器和移动端应用，使用 Client ID 与 PKCE，不生成 Client Secret。'
        }}
        <span v-if="client">客户端类型创建后不可修改。</span>
      </p>
      <FormKit
        v-model="form.description"
        type="textarea"
        name="description"
        label="描述"
        rows="2"
        placeholder="说明应用的用途（可选）"
      />
      <FormKit
        v-model="form.redirectUrisText"
        type="textarea"
        name="redirectUris"
        label="回调地址"
        rows="3"
        validation="required"
        placeholder="https://app.example.com/api/oidc/callback"
        help="每行一个完整地址，需与应用配置一致。使用 HTTPS；本地开发可使用 http://127.0.0.1。"
      />
      <FormKit
        v-model="form.scopes"
        type="checkbox"
        name="scopes"
        label="允许的 Scope"
        help="openid 为必选项；仅开放应用需要的权限。"
        :options="[
          { label: 'openid（必选）', value: 'openid' },
          { label: 'profile', value: 'profile' },
          { label: 'email', value: 'email' },
          { label: 'offline_access（刷新令牌）', value: 'offline_access' },
        ]"
      />
      <FormKit
        v-model="form.accessPolicy"
        type="radio"
        name="accessPolicy"
        label="访问策略"
        :options="[
          { label: '所有已登录用户', value: 'ALL' },
          { label: '仅指定角色', value: 'ROLES' },
        ]"
      />
      <FormKit
        v-if="form.accessPolicy === 'ROLES'"
        v-model="form.roles"
        type="select"
        name="roles"
        label="允许的角色"
        placeholder="搜索角色名称，可多选"
        help="用户拥有任一所选角色即可访问应用。"
        remote
        :remote-option="roleOptions"
        :remote-optimize="false"
        searchable
        multiple
        clearable
        :sortable="false"
        validation="required"
      />
      <FormKit
        v-model="form.enabled"
        type="checkbox"
        name="enabled"
        :label="client ? '启用应用' : '创建后立即启用'"
      />
    </FormKit>
    <template #footer>
      <div class="oidc-client-actions">
        <VButton :disabled="saving" @click="modal?.close()">取消</VButton>
        <VButton type="secondary" :loading="saving" @click="submitForm('oidc-client-form')">
          {{ client ? '保存修改' : '创建应用' }}
        </VButton>
      </div>
    </template>
  </VModal>
</template>

<style>
.oidc-client-modal .modal-header,
.oidc-client-modal .modal-footer {
  flex-shrink: 0;
}

.oidc-client-modal .modal-body {
  min-height: 0;
}

.oidc-client-form-body .formkit-outer,
.oidc-client-form-body .formkit-wrapper,
.oidc-client-form-body .formkit-inner,
.oidc-client-form-body .formkit-fieldset {
  max-width: none !important;
  min-width: 0;
}

.oidc-client-form-body .formkit-fieldset {
  width: 100%;
}

.oidc-client-form-body .formkit-outer {
  padding-top: 12px;
  padding-bottom: 12px;
}

.oidc-client-form-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
}

.oidc-client-form-row .formkit-outer {
  padding: 0;
}

.oidc-client-type-help {
  margin: 8px 0 12px;
  color: #6b7280;
  font-size: 12px;
  line-height: 1.6;
}

.oidc-client-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

@media (max-width: 639px) {
  .oidc-client-form-row {
    grid-template-columns: minmax(0, 1fr);
    gap: 16px;
  }
}
</style>
