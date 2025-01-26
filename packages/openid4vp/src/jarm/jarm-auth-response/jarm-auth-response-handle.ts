import * as v from 'valibot'

import {
  type CallbackContext,
  Oauth2Error,
  decodeJwt,
  jwtSignerFromJwt,
  vCompactJwe,
  vCompactJwt,
} from '@openid4vc/oauth2'
import { jarmAuthResponseValidate } from './jarm-validate-auth-response.js'
import { JarmAuthResponse, JarmAuthResponseEncryptedOnly } from './m-jarm-auth-response.js'

/**
 * The client decrypts the JWT using the default key for the respective issuer or,
 * if applicable, determined by the kid JWT header parameter.
 * The key might be a private key, where the corresponding public key is registered
 * with the expected issuer of the response ("use":"enc" via the client's metadata jwks or jwks_uri)
 * or a key derived from its client secret (see Section 2.2).
 */
const decryptJarmRequestData = async (options: {
  request_data: string
  callbacks: Pick<CallbackContext, 'decryptJwe'>
}) => {
  const { request_data, callbacks } = options

  const { header } = decodeJwt({ jwt: request_data })
  if (!header.kid) {
    throw new Oauth2Error('Jarm JWE is missing the protected header field "kid".')
  }

  const result = await callbacks.decryptJwe(request_data)
  if (!result.decrypted) {
    throw new Oauth2Error('Failed to decrypt jarm auth response.')
  }

  return result.plaintext
}

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export async function jarmAuthResponseHandle(options: {
  jarm_auth_response_jwt: string
  getAuthRequest: (
    authResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
  ) => Promise<{ auth_request: { client_id: string } }>
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'>
}) {
  const { jarm_auth_response_jwt } = options

  const requestDataIsEncrypted = v.is(vCompactJwe, jarm_auth_response_jwt)
  const decryptedRequestData = requestDataIsEncrypted
    ? await decryptJarmRequestData({ request_data: jarm_auth_response_jwt, callbacks: options.callbacks })
    : jarm_auth_response_jwt

  const responseIsSigned = v.is(vCompactJwt, decryptedRequestData)
  if (!requestDataIsEncrypted && !responseIsSigned) {
    throw new Oauth2Error('Jarm Auth Response must be either encrypted, signed, or signed and encrypted.')
  }

  let jarmAuthResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly

  if (responseIsSigned) {
    const { header: jwsProtectedHeader, payload: jwsPayload } = decodeJwt({
      jwt: decryptedRequestData,
    })

    const response = v.parse(JarmAuthResponse, jwsPayload)

    if (!jwsProtectedHeader.kid) {
      throw new Oauth2Error('Jarm JWS is missing the protected header field "kid".')
    }

    const jwtSigner = jwtSignerFromJwt({ header: jwsProtectedHeader, payload: jwsPayload })
    const verificationResult = await options.callbacks.verifyJwt(jwtSigner, {
      compact: decryptedRequestData,
      header: jwsProtectedHeader,
      payload: jwsPayload,
    })

    if (!verificationResult.verified) {
      throw new Oauth2Error('Jarm Auth Response is not valid.')
    }

    jarmAuthResponse = response
  } else {
    const jsonRequestData: unknown = JSON.parse(decryptedRequestData)
    jarmAuthResponse = v.parse(JarmAuthResponseEncryptedOnly, jsonRequestData)
  }

  const { auth_request } = await options.getAuthRequest(jarmAuthResponse)

  jarmAuthResponseValidate({ auth_request, auth_response: jarmAuthResponse })

  let type: 'signed encrypted' | 'encrypted' | 'signed'
  if (responseIsSigned && requestDataIsEncrypted) {
    type = 'signed encrypted'
  } else if (requestDataIsEncrypted) {
    type = 'encrypted'
  } else {
    type = 'signed'
  }

  const issuer = jarmAuthResponse.iss
  return { auth_request, auth_response: jarmAuthResponse, type, issuer }
}
