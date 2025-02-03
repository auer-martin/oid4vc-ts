import { Oauth2Error } from '@openid4vc/oauth2'
import { vCompactJwt } from '@openid4vc/oauth2'
import { parseIfJson } from '@openid4vc/utils'
import * as v from 'valibot'
import type { VpToken } from './v-vp-token.js'

export type VpTokenPresentationParseResult =
  | {
      format: 'dc+sd-jwt'
      presentation: string
      path: string
    }
  | {
      format: 'mso_mdoc'
      presentation: string
      path: string
    }
  | {
      format: 'jwt_vp_json'
      presentation: string
      path: string
    }
  | {
      format: 'ldp_vp'
      presentation: Record<string, unknown>
      path: string
    }
  | {
      format: 'ac_vp'
      presentation: Record<string, unknown>
      path: string
    }

export function parsePresentationsFromVpToken(options: { vp_token: VpToken }): [
  VpTokenPresentationParseResult,
  ...VpTokenPresentationParseResult[],
] {
  const { vp_token: _vp_token } = options
  const vp_token = parseIfJson(_vp_token)

  if (Array.isArray(vp_token)) {
    if (vp_token.length === 0) {
      throw new Oauth2Error('Could not parse vp_token. vp_token is an empty array.')
    }
    return vp_token.map((token, idx) =>
      parseSinglePresentationsFromVpToken({ vp_token: token, path: `$[${idx}]` })
    ) as [VpTokenPresentationParseResult, ...VpTokenPresentationParseResult[]]
  }

  if (typeof vp_token === 'string' || typeof vp_token === 'object') {
    return [parseSinglePresentationsFromVpToken({ vp_token, path: '$' })]
  }

  throw new Oauth2Error(
    `Could not parse vp_token. Expected a string or an array of strings. Received: ${typeof vp_token}`
  )
}

export function parseSinglePresentationsFromVpToken(options: {
  vp_token: unknown
  path: string
}): VpTokenPresentationParseResult {
  const { vp_token: _vp_token } = options

  const vp_token = parseIfJson(_vp_token)

  if (v.is(v.record(v.string(), v.unknown()), vp_token) && (vp_token['@context'] || vp_token.verifiableCredential)) {
    return {
      format: 'ldp_vp',
      presentation: vp_token,
      path: options.path,
    }
  }

  if (v.is(v.record(v.string(), v.unknown()), vp_token) && (vp_token.schema_id || vp_token.cred_def_id)) {
    return {
      format: 'ac_vp',
      presentation: vp_token,
      path: options.path,
    }
  }

  if (typeof vp_token !== 'string') {
    throw new Oauth2Error(
      `Could not parse vp_token. Expected a string, since the vp_token is neither a ldp_vp nor an ac_vp. Received: ${typeof vp_token}`
    )
  }

  if (vp_token.includes('~')) {
    return {
      format: 'dc+sd-jwt',
      presentation: vp_token,
      path: options.path,
    }
  }

  if (v.is(vCompactJwt, vp_token)) {
    return {
      format: 'jwt_vp_json',
      presentation: vp_token,
      path: options.path,
    }
  }

  // if it is a string, and neither of the above, we assume it is a mso_mdoc presentation
  return {
    format: 'mso_mdoc',
    presentation: vp_token,
    path: options.path,
  }
}
