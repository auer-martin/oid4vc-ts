import { vJwkSet } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { vVpFormats } from './v-vp-formats.js'

// Authoritative data the Wallet is able to obtain about the Client from other sources,
// for example those from an OpenID Federation Entity Statement, take precedence over the values passed in client_metadata.
export const vClientMetadata = v.object({
  jwks: v.optional(vJwkSet),
  vp_formats: v.optional(vVpFormats),
  authorization_signed_response_alg: v.optional(v.string(), 'RS256'),
  authorization_encrypted_response_alg: v.optional(v.string()),
  authorization_encrypted_response_enc: v.optional(v.string()), // The default if authorization_signed_response_alg is provided is 'A128CBC-HS256'
})
export type ClientMetadata = v.InferOutput<typeof vClientMetadata>
