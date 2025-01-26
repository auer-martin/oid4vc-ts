import type { CallbackContext } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { parseClientIdentifier } from '../client-identifier-scheme/parse-client-identifier-scheme.js'
import { verifyJarRequest } from '../jar/index.js'
import { type JarAuthRequest, vJarAuthRequest } from '../jar/v-jar-auth-request.js'
import type { WalletMetadata } from '../v-wallet-metadata.js'
import { type Openid4vpAuthRequest, vOpenid4vpAuthRequest } from './v-openid4vp-auth-request.js'
import { validateOpenid4vpAuthRequestParams } from './validate-openid4vp-auth-request.js'

export async function processOpenid4vpAuthRequest(
  params: Openid4vpAuthRequest | JarAuthRequest,
  options: {
    wallet?: {
      nonce?: string
      metadata?: WalletMetadata
    }
    callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe'>
  }
) {
  const { wallet, callbacks } = options
  let kid: string | undefined

  let authRequestParams: Openid4vpAuthRequest

  let jar: Awaited<ReturnType<typeof verifyJarRequest>> | undefined

  if (v.is(vJarAuthRequest, params)) {
    jar = await verifyJarRequest({ jar_request_params: params, callbacks, wallet })
    kid = jar.signerJwk.kid
    authRequestParams = v.parse(vOpenid4vpAuthRequest, jar.auth_request_params)
  } else {
    authRequestParams = params
  }

  validateOpenid4vpAuthRequestParams(authRequestParams, { wallet: options.wallet })

  const clientMeta = parseClientIdentifier({ request: authRequestParams, kid })

  let pex:
    | {
        presentation_definition: unknown
        presentation_definition_uri?: string
      }
    | undefined

  if (authRequestParams.presentation_definition || authRequestParams.presentation_definition_uri) {
    if (authRequestParams.presentation_definition_uri) {
      throw new Error('presentation_definition_uri is not supported')
    }
    pex = {
      presentation_definition: authRequestParams.presentation_definition,
      presentation_definition_uri: authRequestParams.presentation_definition_uri,
    }
  }

  return {
    request: authRequestParams,
    jar,
    client: {
      ...clientMeta,
    },
    pex,
  }
}

export type VerifiedOpenid4vpAuthRequest = Awaited<ReturnType<typeof processOpenid4vpAuthRequest>>
