import { definePlugin } from '@halo-dev/ui-shared'
import { IconPlug } from '@halo-dev/components'
import { markRaw } from 'vue'
import AuthorizationsTab from './components/AuthorizationsTab.vue'

export default definePlugin({
  components: {},
  routes: [
    {
      parentName: 'Root',
      route: {
        path: '/oidc-server',
        name: 'OidcServer',
        component: () => import('./views/ClientsView.vue'),
        meta: {
          title: 'OIDC 应用',
          permissions: ['plugin:oidc-server:manage'],
          searchable: true,
          menu: {
            name: 'OIDC 应用',
            group: 'system',
            icon: markRaw(IconPlug),
            priority: 45,
          },
        },
      },
    },
  ],
  extensionPoints: {
    'uc:user:profile:tabs:create': () => [
      {
        id: 'oidc-server:authorizations',
        label: '应用授权',
        component: markRaw(AuthorizationsTab),
        priority: 20,
      },
    ],
  },
})
