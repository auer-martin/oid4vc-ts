import type { CallbackContext } from '@openid4vc/oauth2'
import { ContentType, defaultFetcher, uriEncodeObject } from '@openid4vc/utils'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request.js'
import type { Openid4vpAuthResponse } from './v-openid4vp-auth-response.js'

export async function submitOpenid4vpAuthorizationResponse(input: {
  request: Pick<Openid4vpAuthRequest, 'redirect_uri' | 'response_uri'>
  response: Openid4vpAuthResponse
  callbacks: Pick<CallbackContext, 'fetch'>
}) {
  const { request, response, callbacks } = input

  const encodedResponse = uriEncodeObject(response)

  const url = request.redirect_uri ?? request.response_uri
  if (!url) {
    throw new Error('No redirect_uri or response_uri provided')
  }

  const fetch = callbacks.fetch ?? defaultFetcher
  const submissionResponse = await fetch(url, {
    method: 'POST',
    body: encodedResponse,
    headers: {
      'Content-Type': ContentType.XWwwFormUrlencoded,
    },
  })

  return {
    response: submissionResponse,
  }
}
