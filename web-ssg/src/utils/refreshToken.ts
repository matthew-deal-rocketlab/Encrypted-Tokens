'use client'

import { ApiStatus, jsonPost } from '@/services/apiclient'
import {
  API_BASE_URL,
  API_STATIC_KEY,
  KEY_JWT_TOKEN,
  KEY_REFRESH_TOKEN,
  passphrase,
  salt,
} from '@/constants'
import { decryptToken, deriveKey, encryptToken } from './crypto-utils'

type AuthRefreshResult = {
  authRefresh?: {
    token?: string
    refreshToken?: string
  }
}
export async function refreshTokenHelper() {
  const refreshTokenData = localStorage.getItem(KEY_REFRESH_TOKEN)
  if (!refreshTokenData) {
    console.error('No refresh token data available.')
    return false
  }

  const { encryptedRefresh, ivRefresh } = JSON.parse(refreshTokenData)
  if (!encryptedRefresh || Object.keys(encryptedRefresh).length === 0) {
    console.error('Invalid encrypted refresh token data:', encryptedRefresh)
    return false
  }

  const key = await deriveKey(passphrase, salt)
  let currentRefreshToken
  try {
    currentRefreshToken = await decryptToken(
      key,
      new Uint8Array(encryptedRefresh),
      new Uint8Array(ivRefresh),
    )
  } catch (error) {
    console.error('Decryption failed:', error)
    return false
  }

  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'x-api-key': API_STATIC_KEY,
  }

  const payload = { authRefresh: { refreshToken: currentRefreshToken } }
  let apiResponse
  try {
    apiResponse = await jsonPost(`${API_BASE_URL}/jsonql`, {
      headers,
      body: JSON.stringify(payload),
    })
  } catch (error) {
    console.error('API request failed:', error)
    return false
  }

  if (apiResponse.status !== ApiStatus.OK || !apiResponse.result) {
    console.error('API response not OK or no result:', apiResponse)
    return false
  }

  const result = apiResponse.result as AuthRefreshResult
  if (!result.authRefresh?.token || !result.authRefresh.refreshToken) {
    console.error('API did not return valid refresh tokens:', result)
    return false
  }

  try {
    const { encrypted: encryptedJwt, iv: ivJwt } = await encryptToken(key, result.authRefresh.token)
    const { encrypted: encryptedRefresh, iv: ivRefresh } = await encryptToken(
      key,
      result.authRefresh.refreshToken,
    )

    localStorage.setItem(
      KEY_JWT_TOKEN,
      JSON.stringify({
        encryptedJwt: Array.from(new Uint8Array(encryptedJwt)),
        ivJwt: Array.from(new Uint8Array(ivJwt)),
      }),
    )
    localStorage.setItem(
      KEY_REFRESH_TOKEN,
      JSON.stringify({
        encryptedRefresh: Array.from(new Uint8Array(encryptedRefresh)),
        ivRefresh: Array.from(new Uint8Array(ivRefresh)),
      }),
    )
  } catch (error) {
    console.error('Failed to encrypt or store new tokens:', error)
    return false
  }

  return true
}
