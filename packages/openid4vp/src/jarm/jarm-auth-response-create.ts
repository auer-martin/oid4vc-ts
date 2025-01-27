import {
  type CallbackContext,
  type JwtEncryptor,
  type JwtSigner,
  Oauth2Error,
  jwtHeaderFromJwtSigner,
} from '@openid4vc/oauth2'
import type { JarmAuthResponse, JarmAuthResponseEncryptedOnly } from './jarm-auth-response/m-jarm-auth-response.js'

export interface CreateJarmAuthResponseOptions {
  jarmAuthResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
  jwtSigner?: JwtSigner
  jwtEncryptor?: JwtEncryptor
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}

export async function createJarmAuthResponse(input: CreateJarmAuthResponseOptions) {
  const { jarmAuthResponse, jwtEncryptor, jwtSigner, callbacks } = input
  if (!jwtSigner && jwtEncryptor) {
    const { jwe } = await callbacks.encryptJwe(jwtEncryptor, JSON.stringify(jarmAuthResponse))
    return { jarm_auth_response_jwt: jwe }
  }

  if (jwtSigner && !jwtEncryptor) {
    const signed = await callbacks.signJwt(jwtSigner, {
      header: jwtHeaderFromJwtSigner(jwtSigner),
      payload: jarmAuthResponse,
    })
    return { jarm_auth_response_jwt: signed.jwt }
  }

  if (!jwtSigner || !jwtEncryptor) {
    throw new Oauth2Error('JWT signer and/or encryptor are required to create a JARM auth response.')
  }
  const signed = await callbacks.signJwt(jwtSigner, {
    header: jwtHeaderFromJwtSigner(jwtSigner),
    payload: jarmAuthResponse,
  })

  const encrypted = await callbacks.encryptJwe(jwtEncryptor, signed.jwt)

  return { jarm_auth_response_jwt: encrypted.jwe }
}
