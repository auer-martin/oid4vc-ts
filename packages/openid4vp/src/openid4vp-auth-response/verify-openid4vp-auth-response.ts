import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request.js'
import {
  type VpTokenPresentationParseResult,
  parsePresentationsFromVpToken,
  parseSinglePresentationsFromVpToken,
} from '../vp-token/parse-presentations-from-vp-token.js'
import type { Openid4vpAuthResponse } from './v-openid4vp-auth-response'

export type VerifyOpenid4VpAuthorizationResponseResult =
  | {
      type: 'pex'
      pex: {
        presentation_submission: unknown
        presentations: [VpTokenPresentationParseResult, ...VpTokenPresentationParseResult[]]
      } & (
        | {
            scope: string
            presentation_definition?: never
          }
        | {
            scope?: never
            presentation_definition: Record<string, unknown> | string
          }
      )
    }
  | {
      type: 'dcql'
      dcql: {
        presentation: VpTokenPresentationParseResult
      } & (
        | {
            scope: string
            query?: never
          }
        | {
            scope?: never
            query: unknown
          }
      )
    }

/**
 * The following steps need to be done manually
    // validating the id token
    // verifying the presentations
    // validating the presentations against the presentation definition
    // checking the revocation status of the presentations
    // checking the nonce of the presentations matches the nonce of the request
 */
export function verifyOpenid4vpAuthorizationResponse(options: {
  requestParams: Openid4vpAuthRequest
  responseParams: Openid4vpAuthResponse
}): VerifyOpenid4VpAuthorizationResponseResult {
  const { requestParams, responseParams } = options
  // todo i think the response prarms  should also contain a nonce
  if (!responseParams.vp_token) {
    throw new Oauth2Error('vp_token is required')
  }

  // The response should not contain a nonce. It should be in the presentation
  if (responseParams.nonce && requestParams.nonce !== responseParams.nonce) {
    throw new Oauth2Error('OpenId4Vp Authorization Response nonce mismatch.')
  }

  if (requestParams.state !== responseParams.state) {
    throw new Oauth2Error('OpenId4Vp Authorization Response state mismatch.')
  }

  // TODO: implement id_token handling
  if (responseParams.id_token) {
    throw new Oauth2Error('OpenId4Vp Authorization Response id_token is not supported.')
  }

  if (responseParams.presentation_submission) {
    if (!requestParams.presentation_definition) {
      throw new Oauth2Error('OpenId4Vp Authorization Request is missing the required presentation_definition.')
    }

    const presentations = parsePresentationsFromVpToken({ vp_token: responseParams.vp_token })
    return {
      type: 'pex',
      pex: requestParams.scope
        ? {
            scope: requestParams.scope,
            presentation_submission: responseParams.presentation_submission,
            presentations,
          }
        : {
            presentation_definition: requestParams.presentation_definition,
            presentation_submission: responseParams.presentation_submission,
            presentations,
          },
    }
  }

  if (requestParams.dcql_query) {
    if (Array.isArray(responseParams.vp_token)) {
      throw new Oauth2Error(
        'The OpenId4Vp Authorization Response contains multiple vp_token values. In combination with dcql this is not possible.'
      )
    }

    if (typeof responseParams.vp_token === 'string') {
      throw new Oauth2Error('If DCQL was used the vp_token must be a JSON-encoded object.')
    }

    const presentation = parseSinglePresentationsFromVpToken({ vp_token: responseParams.vp_token, path: '$' })
    return {
      type: 'dcql',
      dcql: requestParams.scope
        ? {
            scope: requestParams.scope,
            presentation,
          }
        : {
            query: requestParams.dcql_query,
            presentation,
          },
    }
  }

  throw new Oauth2Error(
    'Invalid OpenId4Vp Authorization Response. Response neither contains a presentation_submission nor a dcql presentation.'
  )
}
