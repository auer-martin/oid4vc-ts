import { type CallbackContext, type JwtSigner, Oauth2Error } from '@openid4vc/oauth2'
import { type JarmServerMetadata, jarmAssertMetadataSupported } from '../jarm/index.js'
import { createJarmAuthResponse } from '../jarm/jarm-auth-response-create.js'
import { extractJwksFromClientMetadata } from '../jarm/jarm-extract-jwks.js'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request.js'
import type { Openid4vpAuthResponse } from './v-openid4vp-auth-response.js'

export async function createOpenid4vpAuthorizationResponse(options: {
  requestParams: Pick<Openid4vpAuthRequest, 'state' | 'client_metadata' | 'nonce' | 'response_mode'>
  responseParams: Openid4vpAuthResponse & { state?: never }
  jarm?: {
    jwtSigner?: JwtSigner
    // biome-ignore lint/complexity/noBannedTypes: <explanation>
    jweEncryptor?: {
      nonce: string
    }
    serverMetadata: JarmServerMetadata
    iss?: string // The issuer URL of the authorization server that created the response
    aud?: string // The client_id of the client the response is intended for
    exp?: number // The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
  }
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}) {
  const { requestParams, responseParams, jarm, callbacks } = options

  const openid4vpAuthResponseParams = {
    ...responseParams,
    state: requestParams.state,
  } satisfies Openid4vpAuthResponse

  if (!requestParams.response_mode.includes('jwt')) {
    return { responseParams: openid4vpAuthResponseParams }
  }

  if (!jarm) {
    throw new Oauth2Error(`JARM is required for response mode ${requestParams.response_mode}`)
  }

  let additionalJwtPayload: Record<string, string | number> | undefined

  if (!requestParams.client_metadata) {
    throw new Oauth2Error('Missing client metadata')
  }

  const supportedJarmMetadata = jarmAssertMetadataSupported({
    client_metadata: requestParams.client_metadata,
    server_metadata: jarm.serverMetadata,
  })

  if (jarm.jwtSigner && !jarm.jweEncryptor) {
    throw new Oauth2Error('Only JARM encryption is supported for OpenID4VP')
  }

  // When the response is NOT only encrypted, the JWT payload needs to include the iss and aud exp.
  if (!jarm.jweEncryptor || jarm.jwtSigner) {
    if (!jarm.iss) {
      throw new Oauth2Error('Missing required iss in JARM configuration for creating OpenID4VP authorization response.')
    }

    if (!jarm.aud) {
      throw new Oauth2Error('Missing required aud in JARM configuration for creating OpenID4VP authorization response.')
    }

    additionalJwtPayload = {
      iss: jarm.iss,
      aud: jarm.aud,
      exp: jarm.exp ?? Math.floor(Date.now() / 1000) + 60 * 10,
    }
  }

  const jarmResponseParams = {
    ...openid4vpAuthResponseParams,
    ...additionalJwtPayload,
  }

  if (!requestParams.client_metadata.jwks) {
    throw new Oauth2Error('Missing JWKS in client metadata')
  }

  const clientMetaJwks = extractJwksFromClientMetadata({
    ...requestParams.client_metadata,
    jwks: requestParams.client_metadata.jwks,
  })

  if (!clientMetaJwks?.encJwk) {
    throw new Oauth2Error('Missing encryption JWK')
  }

  if (supportedJarmMetadata.type !== 'encrypt' && supportedJarmMetadata.type !== 'sign_encrypt') {
    throw new Oauth2Error('JARM encryption is not supported for OpenID4VP')
  }

  const result = await createJarmAuthResponse({
    jarmAuthResponse: jarmResponseParams,
    jwtSigner: jarm.jwtSigner,
    jwtEncryptor: jarm.jweEncryptor
      ? {
          method: 'jwk',
          publicJwk: clientMetaJwks.encJwk,
          apu: jarm.jweEncryptor.nonce,
          apv: requestParams.nonce,
          alg: supportedJarmMetadata.client_metadata.authorization_encrypted_response_alg,
          enc: supportedJarmMetadata.client_metadata.authorization_encrypted_response_enc,
        }
      : undefined,
    callbacks: {
      signJwt: callbacks.signJwt,
      encryptJwe: callbacks.encryptJwe,
    },
  })

  return {
    responseParams: jarmResponseParams satisfies Openid4vpAuthResponse,
    jarm: { responseJwt: result.jarm_auth_response_jwt },
  }
}
