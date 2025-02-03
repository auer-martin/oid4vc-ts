import { vJwkSet } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { JarmClientMetadata } from '../jarm/metadata/m-jarm-dcr-metadata.js'
import { vVpFormats } from './v-vp-formats.js'

// Authoritative data the Wallet is able to obtain about the Client from other sources,
// for example those from an OpenID Federation Entity Statement, take precedence over the values passed in client_metadata.
export const vClientMetadata = v.object({
  jwks: v.optional(vJwkSet),
  vp_formats: v.optional(vVpFormats),
  ...JarmClientMetadata.entries,
})
export type ClientMetadata = v.InferOutput<typeof vClientMetadata>
