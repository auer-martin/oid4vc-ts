import { Oauth2Error } from '@openid4vc/oauth2'
import * as v from 'valibot'

export const JarmSignOnlyClientMetadata = v.object({
  authorization_signed_response_alg: v.pipe(
    v.string(),
    v.description(
      'JWA. If this is specified, the response will be signed using JWS and the configured algorithm. The algorithm none is not allowed.'
    )
  ),

  authorization_encrypted_response_alg: v.optional(v.never()),
  authorization_encrypted_response_enc: v.optional(v.never()),
})
export type JarmSignOnlyClientMetadata = v.InferOutput<typeof JarmSignOnlyClientMetadata>

export const JarmEncryptOnlyClientMetadata = v.object({
  authorization_signed_response_alg: v.optional(v.never()),
  authorization_encrypted_response_alg: v.pipe(
    v.string(),
    v.description(
      'JWE alg algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.'
    )
  ),

  authorization_encrypted_response_enc: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWE enc algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.'
    )
  ),
})
export type JarmEncryptOnlyClientMetadata = v.InferOutput<typeof JarmEncryptOnlyClientMetadata>

export const JarmSignEncryptClientMetadata = v.object({
  authorization_signed_response_alg: JarmSignOnlyClientMetadata.entries.authorization_signed_response_alg,
  authorization_encrypted_response_alg: JarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_alg,
  authorization_encrypted_response_enc: JarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_enc,
})
export type JarmSignEncryptClientMetadata = v.InferOutput<typeof JarmSignEncryptClientMetadata>

/**
 * Clients may register their public encryption keys using the jwks_uri or jwks metadata parameters.
 */
export const JarmClientMetadata = v.object({
  authorization_signed_response_alg: v.optional(JarmSignOnlyClientMetadata.entries.authorization_signed_response_alg),
  authorization_encrypted_response_alg: v.optional(
    JarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_alg
  ),
  authorization_encrypted_response_enc: v.optional(
    JarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_enc
  ),
})
export namespace JarmClientMetadata {
  export type Input = v.InferInput<typeof JarmClientMetadata>
  export type Output = v.InferOutput<typeof JarmClientMetadata>
}
export type JarmClientMetadata = JarmClientMetadata.Output

export const JarmClientMetadataParsed = v.pipe(
  JarmClientMetadata,
  v.transform((client_metadata) => {
    if (v.is(JarmSignEncryptClientMetadata, client_metadata)) {
      return {
        type: 'sign_encrypt',
        client_metadata: {
          ...client_metadata,
          authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc ?? 'A128CBC-HS256',
        },
      } as const
    }

    if (v.is(JarmEncryptOnlyClientMetadata, client_metadata)) {
      return {
        type: 'encrypt',
        client_metadata: {
          ...client_metadata,
          authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc ?? 'A128CBC-HS256',
        },
      } as const
    }

    // this must be the last entry
    if (v.is(JarmSignOnlyClientMetadata, client_metadata)) {
      return {
        type: 'sign',
        client_metadata: {
          ...client_metadata,
          authorization_signed_response_alg: client_metadata.authorization_signed_response_alg ?? 'RS256',
        },
      } as const
    }

    throw new Oauth2Error('Invalid client metadata')
  })
)
export type JarmClientMetadataParsed = v.InferOutput<typeof JarmClientMetadataParsed>
