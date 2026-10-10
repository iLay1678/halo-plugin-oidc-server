export const scopeLabels: Record<string, string> = {
  openid: '基本身份',
  profile: '个人资料',
  email: '邮箱',
  offline_access: '保持授权',
}

export function describeScopes(scopes: string[] | undefined): string {
  return (scopes ?? []).map((scope) => scopeLabels[scope] ?? scope).join('、')
}

export function splitRedirectUris(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  ]
}
