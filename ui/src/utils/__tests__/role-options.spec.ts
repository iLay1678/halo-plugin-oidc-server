import { describe, expect, it, vi } from 'vitest'
import { createRoleOptions } from '../role-options'

describe('角色候选回填', () => {
  it('搜索不会更改已选角色，回填逐个查询并精确匹配', async () => {
    const load = vi.fn(async (keyword: string) => [
      { label: '近似角色', value: `${keyword}-other` },
      { label: `角色 ${keyword}`, value: keyword },
    ])
    const options = createRoleOptions(load)
    const selected = ['editor', 'guest']
    await options.search({ keyword: 'admin', page: 1, size: 20 })
    const values = await options.findOptionsByValues(selected)
    expect(values).toEqual([
      { label: '角色 editor', value: 'editor' },
      { label: '角色 guest', value: 'guest' },
    ])
    expect(selected).toEqual(['editor', 'guest'])
    expect(load).toHaveBeenCalledWith('editor')
    expect(load).toHaveBeenCalledWith('guest')
  })

  it('网络失败或角色缺失时保留原始权限值', async () => {
    const options = createRoleOptions(async (keyword) => {
      if (keyword === 'offline') throw new Error('网络中断')
      return []
    })
    expect(await options.findOptionsByValues(['deleted', 'offline'])).toEqual([
      { label: 'deleted', value: 'deleted' },
      { label: 'offline', value: 'offline' },
    ])
  })

  it('搜索失败向调用方报告错误', async () => {
    const options = createRoleOptions(async () => {
      throw new Error('无法加载角色')
    })
    await expect(options.search({ keyword: '', page: 1, size: 20 })).rejects.toThrow('无法加载角色')
  })
})
