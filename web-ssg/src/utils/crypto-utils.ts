'use client'

// Function to derive a cryptographic key from a passphrase
export async function deriveKey(passphrase: string, salt: string) {
  const encoder = new TextEncoder()
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )
  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )
}

export async function encryptToken(key: CryptoKey, token: string) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)) // Initialization Vector
  const encoded = new TextEncoder().encode(token)
  try {
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded)
    return { encrypted, iv }
  } catch (error) {
    throw new Error('Encryption failed')
  }
}

export async function decryptToken(key: CryptoKey, encrypted: any, iv: any) {
  // Convert the array back to Uint8Array properly
  const encryptedTypedArray = new Uint8Array(encrypted)
  const encryptedBuffer = encryptedTypedArray.buffer.slice(
    encryptedTypedArray.byteOffset,
    encryptedTypedArray.byteOffset + encryptedTypedArray.byteLength,
  )
  const ivArray = new Uint8Array(iv)
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivArray },
      key,
      encryptedBuffer,
    )
    return new TextDecoder().decode(decrypted)
  } catch (error) {
    console.error('Decryption error:', error)
    throw new Error('Decryption failed')
  }
}
