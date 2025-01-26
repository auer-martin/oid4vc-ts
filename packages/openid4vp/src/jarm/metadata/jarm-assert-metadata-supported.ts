import { Oauth2Error } from '@openid4vc/oauth2'
import * as v from 'valibot'
import type { JarmServerMetadata } from './m-jarm-as-metadata.js'
import { type JarmClientMetadata, JarmClientMetadataParsed } from './m-jarm-dcr-metadata.js'

interface AssertValueSupported<T> {
  supported: T[]
  actual: T
  error: Error
}

function assertValueSupported<T>(input: AssertValueSupported<T>): T {
  const { error, supported, actual } = input
  const intersection = supported.find((value) => value === actual)

  if (!intersection) {
    throw error
  }

  return intersection
}

export function jarmAssertMetadataSupported(input: {
  client_metadata: JarmClientMetadata.Input
  server_metadata: JarmServerMetadata.Input
}) {
  const { client_metadata, server_metadata } = input
  const parsedClientMetadata = v.parse(JarmClientMetadataParsed, client_metadata)

  if (parsedClientMetadata.type === 'sign_encrypt' || parsedClientMetadata.type === 'encrypt') {
    if (server_metadata.authorization_encryption_alg_values_supported) {
      assertValueSupported({
        supported: server_metadata.authorization_encryption_alg_values_supported,
        actual: parsedClientMetadata.client_metadata.authorization_encrypted_response_alg,
        error: new Oauth2Error('Invalid authorization_encryption_alg'),
      })
    }

    if (server_metadata.authorization_encryption_enc_values_supported) {
      assertValueSupported({
        supported: server_metadata.authorization_encryption_enc_values_supported,
        actual: parsedClientMetadata.client_metadata.authorization_encrypted_response_enc,
        error: new Oauth2Error('Invalid authorization_encryption_enc'),
      })
    }
  }

  if (
    server_metadata.authorization_signing_alg_values_supported &&
    (parsedClientMetadata.type === 'sign' || parsedClientMetadata.type === 'sign_encrypt')
  ) {
    assertValueSupported({
      supported: server_metadata.authorization_signing_alg_values_supported,
      actual: parsedClientMetadata.client_metadata.authorization_signed_response_alg,
      error: new Oauth2Error('Invalid authorization_signed_response_alg'),
    })
  }

  return parsedClientMetadata
}
