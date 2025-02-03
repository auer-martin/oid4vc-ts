import * as v from 'valibot'

import {
  type CallbackContext,
  type Jwk,
  type JwtSigner,
  Oauth2Error,
  Oauth2ServerErrorResponseError,
  decodeJwt,
  jwtSignerFromJwt,
  vCompactJwe,
  vCompactJwt,
} from '@openid4vc/oauth2'
import type { WalletMetadata } from '../../models/v-wallet-metadata'
import { fetchJarRequestObject } from '../jar-request-object/fetch-jar-request-object'
import { type JarRequestObjectPayload, vJarRequestObjectPayload } from '../jar-request-object/v-jar-request-object'
import { type JarAuthRequest, validateJarAuthRequest } from '../v-jar-auth-request'

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating, decrypting, and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jar_request_params - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(options: {
  jar_request_params: JarAuthRequest
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe'>
  wallet?: {
    metadata?: WalletMetadata
    nonce?: string
  }
}): Promise<{
  auth_request_params: JarRequestObjectPayload
  send_by: 'value' | 'reference'
  encryptionJwk?: Jwk
  signerJwk: Jwk
  jwtSigner: JwtSigner
}> {
  const { jar_request_params, callbacks, wallet } = options

  validateJarAuthRequest({ jar_auth_request: jar_request_params })

  const send_by = jar_request_params.request ? 'value' : 'reference'

  const requestObject =
    jar_request_params.request ??
    (await fetchJarRequestObject(
      // biome-ignore lint/style/noNonNullAssertion:
      jar_request_params.request_uri!,
      jar_request_params.client_id.split(':')[0],
      jar_request_params.request_uri_method ?? 'GET',
      wallet ?? {}
    ))

  const requestObjectIsEncrypted = v.is(vCompactJwe, requestObject as string)
  const { encryptionJwk, payload: decryptedRequestObject } = requestObjectIsEncrypted
    ? await decryptJarRequest({ jwe: requestObject, callbacks })
    : { payload: requestObject, encryptionJwk: undefined }

  const requestIsSigned = v.parse(vCompactJwt, decryptedRequestObject)
  if (!requestIsSigned) {
    throw new Oauth2Error('Jar Request Object is not a valid JWS.')
  }

  const { auth_request_params, signerJwk, jwtSigner } = await verifyJarRequestObject({
    decryptedRequestObject,
    callbacks,
  })
  if (!auth_request_params.client_id) {
    throw new Oauth2Error('Jar Request Object is missing the required "client_id" field.')
  }

  if (jar_request_params.client_id !== auth_request_params.client_id) {
    throw new Oauth2Error('client_id does not match the request object client_id.')
  }

  return {
    send_by,
    auth_request_params,
    signerJwk,
    encryptionJwk,
    jwtSigner,
  }
}

async function decryptJarRequest(options: {
  jwe: string
  callbacks: Pick<CallbackContext, 'decryptJwe'>
}) {
  const { jwe, callbacks } = options

  const { header } = decodeJwt({ jwt: jwe })
  if (!header.kid) {
    throw new Oauth2Error('Jar JWE is missing the protected header field "kid".')
  }

  const decryptionResult = await callbacks.decryptJwe(jwe)
  if (!decryptionResult.decrypted) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'Failed to decrypt jar request object.',
    })
  }

  return decryptionResult
}

async function verifyJarRequestObject(options: {
  decryptedRequestObject: string
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}) {
  const { decryptedRequestObject, callbacks } = options

  const jwt = decodeJwt({ jwt: decryptedRequestObject, payloadSchema: vJarRequestObjectPayload })

  const jwtSigner = jwtSignerFromJwt(jwt)
  const { verified, signerJwk } = await callbacks.verifyJwt(jwtSigner, {
    ...jwt,
    compact: decryptedRequestObject,
  })

  if (!verified) {
    throw new Oauth2Error('Jar Request Object signature verification failed.')
  }

  return { auth_request_params: jwt.payload, signerJwk, jwtSigner }
}
