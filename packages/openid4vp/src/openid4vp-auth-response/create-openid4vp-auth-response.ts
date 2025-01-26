import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request.js'
import type { Openid4vpAuthResponse } from './v-openid4vp-auth-response.js'

export async function createOpenid4vpAuthorizationResponse(input: {
  requestParams: Pick<Openid4vpAuthRequest, 'state'>
  responseParams: Openid4vpAuthResponse & { state?: never }
}) {
  const { requestParams, responseParams } = input

  return {
    ...responseParams,
    state: requestParams.state,
  } satisfies Openid4vpAuthResponse
}
