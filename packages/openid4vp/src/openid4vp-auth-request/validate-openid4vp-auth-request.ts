import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthRequest } from './v-openid4vp-auth-request'

/**
 *
 * @param params
 * @param options
 *  @params options.walletNonce - The nonce value passed by the Wallet in the POST | GET request to fetch the request object.
 */
export const validateOpenid4vpAuthRequestParams = (
  params: Openid4vpAuthRequest,
  options: {
    wallet?: {
      nonce?: string
    }
  }
) => {
  if (params.redirect_uri && !params.response_uri) {
    throw new Oauth2Error('OpenId4Vp Authorization Request redirect_uri is required when response_uri is not provided.')
  }

  if (params.response_uri && !['direct_post', 'direct_post.jwt'].includes(params.response_mode ?? '')) {
    throw new Oauth2Error(
      `OpenId4Vp Authorization Request response_mode must be direct_post or direct_post.jwt when response_uri is provided. Current: ${params.response_mode}`
    )
  }

  if (params.presentation_definition && params.presentation_definition_uri) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request presentation_definition and presentation_definition_uri cannot be provided together.'
    )
  }

  if (
    [params.presentation_definition_uri, params.presentation_definition, params.dcql, params.scope].filter(Boolean)
      .length > 1
  ) {
    throw new Oauth2Error(
      'Exactly one of the following parameters MUST be present in the Authorization Request: dcql_query, presentation_definition, presentation_definition_uri, or a scope value representing a Presentation Definition.'
    )
  }

  if (params.request_uri_method && !params.request_uri) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request request_uri_method parameter MUST NOT be present if the request_uri parameter is not present.'
    )
  }

  if (params.transaction_data) {
    // TODO:The Wallet MUST return an error if a request contains even one unrecognized transaction data type or transaction data not conforming to the respective type definition. In addition to the parameters determined by the type of transaction data
  }

  if (params.trust_chain && (!params.client_id.startsWith('http://') || !params.client_id.startsWith('https://'))) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request trust_chain parameter MUST NOT be present if the client_id is not an OpenId Federation Entity Identifier starting with http:// or https://.'
    )
  }

  if (options.wallet?.nonce && !params.wallet_nonce) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request wallet_nonce parameter is required when wallet_nonce is provided.'
    )
  }

  if (options.wallet?.nonce !== params.wallet_nonce) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request wallet_nonce parameter does not match the wallet_nonce value passed by the Wallet.'
    )
  }
}
