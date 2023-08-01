import crypto from 'crypto';

import { APP_SECRET, ERROR_TOKEN_EXPIRED, JWT_EXPIRY, JWT_REFRESH_EXPIRY, JWT_REFRESH_INTERVAL, JWT_SECRET } from '../constants';
import { btoa, atob } from './converters';
import { uuidv4 } from './misc';
import { Request } from 'express';

export const hashPassword = (pass: string, salt: string): string => {
  const hash = crypto.createHash('sha256');
  hash.update(salt + pass + APP_SECRET);
  const sha256Hash = hash.digest('hex');
  return sha256Hash;
};

export const generateJWT = (payload: object, secret: string): string => {
  // Create the header and payload
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(payload));

  // Create the signature
  const signatureInput = encodedHeader + '.' + encodedPayload;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(signatureInput)
    .digest('base64');

  // Create the JWT
  const jwt = signatureInput + '.' + btoa(signature);
  return jwt;
};

export const getUserJWT = (userID: string): string => {
  var payload = {
    sub: userID,
    rnd: Math.floor(Math.random() * 100000),
    iat: Math.floor(Date.now() / 1000),
  };

  return generateJWT(payload, JWT_SECRET);
};

export const getUserRefreshToken = (userID: string) => {
  var payload = {
    sub: userID,
    rnd: uuidv4(false),
    iat: Math.floor(Date.now() / 1000),
  };

  return generateJWT(payload, JWT_SECRET);
};

// If validated, returns the userId in .result or error message in .error
export const validateToken = (req: Request): FnResult => {
  const jwtRaw = (req.headers['authorization'] ?? '').replace('Bearer ', '');
  const jwtParts = jwtRaw.split('.')
  if (jwtParts.length !== 3) return { error: 'error: token invalid(1)' };

  const jwtPayload = (jwtParts[1] ?? '') as string;
  let payload = null
  try {
    payload = JSON.parse(atob(jwtPayload));
  } catch (_) { }
  if (payload === null) return { error: 'error: token invalid(2)' };

  // check date
  const now = new Date();
  let expiry = new Date(payload.iat * 1000)
  expiry.setSeconds(expiry.getSeconds() + JWT_EXPIRY);
  if (now > expiry) return ERROR_TOKEN_EXPIRED;

  // check signature
  const calculated = generateJWT(payload, JWT_SECRET);
  if (calculated !== jwtRaw) return { error: 'error: token invalid(3)' };

  return { result: payload.sub };
}

interface validateRefreshTokenResult {
  error?: string;
  userId?: string;
  renewDate?: Date;
}

// If validated, returns the userId in .result or error message in .error
export const validateRefreshToken = (refreshToken: string): validateRefreshTokenResult => {
  const jwtParts = refreshToken.split('.')
  if (jwtParts.length !== 3) return { error: 'error: token invalid(1)' };

  const jwtPayload = (jwtParts[1] ?? '') as string;
  let payload = null
  try {
    payload = JSON.parse(atob(jwtPayload));
  } catch (_) { }
  if (payload === null) return { error: 'error: token invalid(2)' };

  // check date
  const now = new Date();
  const iatTime = payload.iat * 1000;
  let expiry = new Date(iatTime)
  expiry.setSeconds(expiry.getSeconds() + JWT_REFRESH_EXPIRY);
  if (now > expiry) return ERROR_TOKEN_EXPIRED;

  // check signature
  const calculated = generateJWT(payload, JWT_SECRET);
  if (calculated !== refreshToken) return { error: 'error: token invalid(3)' };

  let renewDate = new Date(iatTime)
  renewDate.setSeconds(renewDate.getSeconds() + JWT_REFRESH_INTERVAL);

  return {
    userId: payload.sub,
    renewDate: renewDate,
  };
}