import { Oauth2Error } from '@openid4vc/oauth2'
import { URL } from '@openid4vc/utils'

interface JarmAuthResponseSendOptions {
  authRequest: {
    response_uri?: string
    redirect_uri?: string
  }
  jarmAuthResponseJwt: string
}

export const jarmAuthResponseSend = (options: JarmAuthResponseSendOptions) => {
  const { authRequest, jarmAuthResponseJwt } = options

  const responseEndpoint = authRequest.response_uri ?? authRequest.redirect_uri
  if (!responseEndpoint) {
    throw new Oauth2Error('response_uri or redirect_uri is required')
  }

  const responseEndpointUrl = new URL(responseEndpoint)
  return handleDirectPostJwt(responseEndpointUrl, jarmAuthResponseJwt)
}

async function handleDirectPostJwt(responseEndpoint: URL, responseJwt: string) {
  const response = await fetch(responseEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `response=${responseJwt}`,
  })

  return {
    response_mode: 'direct_post.jwt',
    response,
  } as const
}
