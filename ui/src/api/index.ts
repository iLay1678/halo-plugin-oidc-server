import { axiosInstance } from '@halo-dev/api-client'
import { OidcV1alpha1ConsoleApi, OidcV1alpha1UcApi } from './generated'

export const consoleApi = new OidcV1alpha1ConsoleApi(undefined, '', axiosInstance)
export const userApi = new OidcV1alpha1UcApi(undefined, '', axiosInstance)
