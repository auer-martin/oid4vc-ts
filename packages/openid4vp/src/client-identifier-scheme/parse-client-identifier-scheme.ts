import { Oauth2Error, getGlobalConfig } from '@openid4vc/oauth2'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request.js'
import type { ClientMetadata } from '../v-client-metadata.js'
import { type ClientIdScheme, vClientIdScheme } from './v-client-id-scheme.js'

/**
 * Result of parsing a client identifier
 */
export type ParsedClientIdentifier =
  | {
      scheme: 'redirect_uri'
      identifier: string
      originalValue: string
      redirectUri: string
      clientMetadata?: ClientMetadata
    }
  | {
      scheme: 'https'
      identifier: string
      originalValue: string
      trustChain?: unknown
      clientMetadata?: never // clientMetadata must be obtained from the entity statement
    }
  | {
      scheme: 'did'
      identifier: string
      originalValue: string
      kid: string
      clientMetadata?: ClientMetadata
    }
  | {
      scheme: 'verifier_attestation' | 'x509_san_dns' | 'x509_san_uri' | 'pre-registered' | 'web-origin'
      identifier: string
      originalValue: string
      clientMetadata?: ClientMetadata
    }

/**
 * Configuration options for the parser
 */
export interface ClientIdentifierParserConfig {
  supportedSchemes?: ClientIdScheme[]
  requireSignatureFor?: ClientIdScheme[]
}

/**
 * Parse and validate a client identifier
 */
export function parseClientIdentifier(
  options: {
    request: Openid4vpAuthRequest
    kid?: string
  },
  parserConfig?: ClientIdentifierParserConfig
): ParsedClientIdentifier {
  const { request, kid } = options
  const clientId = request.client_id

  if (!clientId?.length) {
    throw new Oauth2Error('Invalid or empty client identifier.')
  }

  // By default require signatures for these schemes
  const parserConfigWithDefaults: Required<ClientIdentifierParserConfig> = {
    supportedSchemes:
      parserConfig?.supportedSchemes ||
      Object.values(vClientIdScheme.options).filter((scheme) => scheme !== 'web-origin'),
    requireSignatureFor:
      parserConfig?.requireSignatureFor ||
      ([
        'did',
        'verifier_attestation',
        'x509_san_dns',
        'x509_san_uri',
        'https',
        'pre-registered',
      ] satisfies ClientIdScheme[]),
  }

  // Check for scheme delimiter
  const colonIndex = clientId.indexOf(':')

  // No scheme delimiter means pre-registered client the default scheme
  if (colonIndex === -1) {
    return {
      scheme: 'pre-registered',
      identifier: clientId,
      originalValue: clientId,
      clientMetadata: request.client_metadata,
    }
  }

  const schemePart = clientId.substring(0, colonIndex)
  const identifierPart = clientId.substring(colonIndex + 1)

  // Validate the scheme is supported
  if (!parserConfigWithDefaults.supportedSchemes.includes(schemePart as ClientIdScheme)) {
    throw new Oauth2Error(`Unsupported client identifier scheme. ${schemePart} is not supported.`)
  }

  const scheme = schemePart as ClientIdScheme

  if (scheme === 'https') {
    const config = getGlobalConfig()
    if (!identifierPart.startsWith('https://') || (config.allowInsecureUrls && identifierPart.startsWith('http://'))) {
      throw new Oauth2Error(
        'Invalid client identifier. Client identifier must start with https:// or http:// if allowInsecureUrls is true.'
      )
    }
    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      trustChain: request.trust_chain,
    }
  }

  if (scheme === 'redirect_uri') {
    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      redirectUri: (request.redirect_uri ?? request.response_uri) as string,
    }
  }

  if (scheme === 'did') {
    if (!identifierPart.startsWith('did:')) {
      throw new Oauth2Error('Invalid client identifier. Client identifier must start with did:')
    }
    if (!kid) {
      throw new Oauth2Error('Missing required kid for client identifier scheme: did')
    }
    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      kid,
    }
  }

  if (scheme === 'web-origin') {
    throw new Oauth2Error('Unsupported client identifier scheme. web-origin is not supported.')
  }

  return {
    scheme,
    identifier: identifierPart,
    originalValue: clientId,
  }
}
