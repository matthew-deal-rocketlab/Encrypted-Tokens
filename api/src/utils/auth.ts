import crypto from 'crypto'

import {
  API_HEADER,
  API_KEY,
  APP_SECRET,
  ERROR_TOKEN_EXPIRED,
  JWT_EXPIRY,
  JWT_REFRESH_EXPIRY,
  JWT_REFRESH_INTERVAL,
  JWT_SECRET,
} from '../constants'
import { btoa, atob } from './converters'
import { JSON_parse, JSON_stringify, uuidv4 } from './misc'
import { Request } from 'express'
import dateToSeconds from './date-to-seconds'

const encryptUserId = (userId: number): string => {
  const rando1 = Math.floor(Math.random() * 100000)
  const rando2 = Math.floor(Math.random() * 100000)

  return `1${rando1}e${userId}e${rando2}`
}

const decryptUserId = (encryptedUserId: string): number => {
  return parseInt(encryptedUserId.split('e')[1] ?? '')
}

export const hashPassword = (pass: string, salt: string): string => {
  const hash = crypto.createHash('sha256')
  hash.update(salt + pass + APP_SECRET)
  const sha256Hash = hash.digest('hex')
  return sha256Hash
}

export const generateJWT = (payload: object, secret: string): string => {
  // Create the header and payload
  const header = { alg: 'HS256', typ: 'JWT' }
  const encodedHeader = btoa(JSON_stringify(header) ?? '')
  const encodedPayload = btoa(JSON_stringify(payload) ?? '')

  // Create the signature
  const signatureInput = encodedHeader + '.' + encodedPayload
  const signature = crypto.createHmac('sha256', secret).update(signatureInput).digest('base64')

  // Create the JWT
  const jwt = signatureInput + '.' + btoa(signature)
  return jwt
}

export const getUserJWT = (userid: number, userUid: string): string => {
  const iat = Math.floor(Date.now() / 1000)

  const payload = {
    sub: userUid,
    // Sticking the user id in between two random numbers should obsecure it from the casual observer
    // having this in the JWT will save a database query
    rnd: encryptUserId(userid),
    iat: iat,
    exp: iat + JWT_EXPIRY,
  }

  return generateJWT(payload, JWT_SECRET)
}

export const getUserRefreshToken = (userID: string) => {
  const iat = Math.floor(Date.now() / 1000)

  const payload = {
    sub: userID,
    rnd: uuidv4(false),
    iat: iat,
    exp: iat + JWT_REFRESH_EXPIRY,
  }

  return generateJWT(payload, JWT_SECRET)
}

// If validated, returns the userId in .result or error message in .error
export const validateToken = (req: Request): FnResult => {
  const jwtRaw = (req.headers['authorization'] ?? '').replace('Bearer ', '')
  const jwtParts = jwtRaw.split('.')
  if (jwtParts.length !== 3) return { error: 'error: token invalid(1)' }

  const jwtPayload = (jwtParts[1] ?? '') as string
  const payload = JSON_parse(atob(jwtPayload))
  if (payload === null) return { error: 'error: token invalid(2)' }

  // check date
  const now = new Date()
  const currentTime = dateToSeconds(now)
  const expiry = payload.exp
  if (currentTime > expiry) {
    console.log('token expired', currentTime, expiry)
    return ERROR_TOKEN_EXPIRED
  }

  // check signature
  const calculated = generateJWT(payload, JWT_SECRET)
  if (calculated !== jwtRaw) {
    console.log('token invalid')
    return { error: 'error: token invalid(3)' }
  }

  return {
    result: {
      uid: payload.sub,
      id: decryptUserId(payload.rnd),
    },
  }
}

interface validateRefreshTokenResult {
  error?: string
  userId?: string
  renewDate?: Date
}

// If validated, returns the userId in .result or error message in .error
export const validateRefreshToken = (refreshToken: string): validateRefreshTokenResult => {
  const jwtParts = refreshToken.split('.')
  if (jwtParts.length !== 3) return { error: 'error: token invalid(1)' }

  const jwtPayload = (jwtParts[1] ?? '') as string
  const payload = JSON_parse(atob(jwtPayload))
  if (payload === null) return { error: 'error: token invalid(2)' }

  // check date
  const now = new Date()
  const iatTime = payload.iat * 1000
  const expiry = new Date(iatTime)
  expiry.setSeconds(expiry.getSeconds() + JWT_REFRESH_EXPIRY)
  if (now > expiry) return ERROR_TOKEN_EXPIRED

  // check signature
  const calculated = generateJWT(payload, JWT_SECRET)
  if (calculated !== refreshToken) return { error: 'error: token invalid(3)' }

  const renewDate = new Date(iatTime)
  renewDate.setSeconds(renewDate.getSeconds() + JWT_REFRESH_INTERVAL)

  return {
    userId: payload.sub,
    renewDate: renewDate,
  }
}

export const validateAPIKey = (req: Request): boolean => {
  const apikey = req.headers[API_HEADER]
  const isValid = apikey === API_KEY
  if (!isValid) req.socket.end()
  return isValid
}

export function salt(): string {
  return crypto.randomBytes(16).toString('base64')
}
