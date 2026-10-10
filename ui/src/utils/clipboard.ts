import { Toast } from '@halo-dev/components'

export async function copyText(value: string) {
  try {
    await navigator.clipboard.writeText(value)
    Toast.success('已复制')
  } catch {
    Toast.error('无法访问剪贴板，请选中文本手动复制')
  }
}
