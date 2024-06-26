'use client'

import { API_BASE_URL, API_STATIC_KEY, KEY_JWT_TOKEN, passphrase, salt } from '@/constants'
import { jsonPost, type ApiResponse } from '@/services/apiclient'
import { refreshTokenHelper } from './refreshToken'
import { decryptToken, deriveKey } from './crypto-utils'

/*
 * This is a wrapper around the jsonPost function from the apiclient.
 * It adds a few things:
 * - It adds the JWT token to the headers
 * - It checks if the JWT token is still valid, and if not, it refreshes the token
 * - It retries the request if the JWT token was refreshed
 */
export const apiPost = async (url: string, data: object): Promise<ApiResponse> => {
  const tokenData = localStorage.getItem(KEY_JWT_TOKEN)
  let jwtToken = ''

  if (tokenData) {
    const { encryptedJwt, ivJwt } = JSON.parse(tokenData)
    const key = await deriveKey(passphrase, salt)
    try {
      jwtToken = await decryptToken(key, encryptedJwt, new Uint8Array(ivJwt))
    } catch (error) {
      console.error('Decryption error:', error)
    }
  }

  const headers = {
    Accept: 'application/json',
    'Content-type': 'application/json',
    'x-api-key': API_STATIC_KEY,
    Authorization: jwtToken ? `Bearer ${jwtToken}` : '',
  }

  const apiResponse = await jsonPost(`${API_BASE_URL}${url}`, {
    headers,
    body: JSON.stringify(data),
  })

  if (apiResponse.status === 419) {
    const refreshed = await refreshTokenHelper()
    if (refreshed) {
      return await apiPost(url, data)
    }
    // If the token could not be refreshed, we should log the user out.
    if (!refreshed) localStorage.removeItem(KEY_JWT_TOKEN)
  }

  return apiResponse // Return the response from API or after refreshing token
}
