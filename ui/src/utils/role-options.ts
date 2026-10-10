export interface RoleOption {
  label: string
  value: string
  description?: string
}

export function createRoleOptions(load: (keyword: string) => Promise<RoleOption[]>) {
  return {
    async search({ keyword }: { keyword: string; page: number; size: number }) {
      const options = await load(keyword)
      return { options, page: 1, size: Math.max(options.length, 20), total: options.length }
    },
    async findOptionsByValues(values: string[]) {
      return Promise.all(
        values.map(async (value) => {
          try {
            const options = await load(value)
            return options.find((option) => option.value === value) ?? { label: value, value }
          } catch {
            // 候选查询失败时保留原角色值，避免编辑应用时意外清空访问策略。
            return { label: value, value }
          }
        }),
      )
    },
  }
}
