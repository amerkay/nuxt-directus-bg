import jwtDecode from 'jwt-decode'
import {
  deleteCookie,
  getCookie,
  setCookie,
  splitCookiesString,
  appendResponseHeader
} from 'h3'

import type { AuthenticationData } from '../types'
import {
  useRequestEvent,
  useRuntimeConfig,
  useState,
  useCookie,
  useRequestHeaders,
  navigateTo
} from '#imports'
import type { CookieSerializeOptions } from 'cookie'

export default function () {
  const event = useRequestEvent()
  const config = useRuntimeConfig().public.directus

  const accessTokenCookieName = config.auth.accessTokenCookieName
  const refreshTokenCookieName = config.auth.refreshTokenCookieName
  const msRefreshBeforeExpires = config.auth.msRefreshBeforeExpires
  const accessTokenCookieExpiresSeconds = config.auth.accessTokenCookieExpiresSeconds
  const loggedInName = 'directus_logged_in'

  const _accessToken = {
    get: () =>
      process.server
        ? event.context[accessTokenCookieName] ||
          getCookie(event, accessTokenCookieName)
        : useCookie(accessTokenCookieName).value,

    set: (value: string) => {
      const cookieOptions: CookieSerializeOptions = {
        sameSite: 'lax',
        secure: true,
        maxAge: accessTokenCookieExpiresSeconds
      }

      if (process.server) {
        event.context[accessTokenCookieName] = value
        setCookie(event, accessTokenCookieName, value, cookieOptions)
      } else {
        useCookie(accessTokenCookieName, cookieOptions).value = value
      }
    },

    clear: () => {
      if (process.server) {
        deleteCookie(event, accessTokenCookieName)
      } else {
        useCookie(accessTokenCookieName).value = null
      }
    }
  }

  const _refreshToken = {
    get: () => process.server && getCookie(event, refreshTokenCookieName)
  }

  const _loggedIn = {
    get: () => process.client && localStorage.getItem(loggedInName),
    set: (value: boolean) =>
      process.client && localStorage.setItem(loggedInName, value.toString())
  }

  async function refresh() {
    const user = useState('directus-user')
    const refreshPromise = useState('directus-refresh-promise')

    // if refreshPromise is not null, it means that the refresh is already in progress
    if (refreshPromise.value) {
      return (await refreshPromise).value
    }

    const cookie = useRequestHeaders(['cookie']).cookie || ''

    refreshPromise.value = $fetch
      .raw<AuthenticationData>('/auth/refresh', {
        baseURL: config.rest.baseUrl,
        method: 'POST',
        credentials: 'include',
        body: {
          mode: 'cookie'
        },
        headers: {
          cookie
        }
      })
      .then(res => {
        const setCookie = res.headers.get('set-cookie') || ''
        const cookies = splitCookiesString(setCookie)
        for (const cookie of cookies) {
          appendResponseHeader(event, 'set-cookie', cookie)
        }
        if (res._data) {
          _accessToken.set(res._data?.data.access_token)
          _loggedIn.set(true)
        }
        refreshPromise.value = null
        return res
      })
      .catch(async () => {
        refreshPromise.value = null

        _accessToken.clear()
        _loggedIn.set(false)
        user.value = null
        if (process.client) {
          await navigateTo(config.auth.redirect.logout)
        }
      })

    return (await refreshPromise).value
  }

  async function getToken(): Promise<string | null | undefined> {
    const accessToken = _accessToken.get()

    if (accessToken && isTokenExpired(accessToken)) {
      await refresh()
    }

    return _accessToken.get()
  }

  function isTokenExpired(token: string) {
    const decoded = jwtDecode(token) as { exp: number }
    const expires = decoded.exp * 1000 - msRefreshBeforeExpires
    return expires < Date.now()
  }

  return { refresh, getToken, _accessToken, _refreshToken, _loggedIn }
}
