# TODO LIST

Make sure to throw proper errors.
IdToken Handling. Also required in openid4vp
Nonce handling to it immediately
// TODO:The Wallet MUST return an error if a request contains even one unrecognized transaction data type or transaction data not conforming to the respective type definition. In addition to the parameters determined by the type of transaction data

# IETF Security Topics

## The authorization Request should extend an oauth request
## Validate the authorization request accoriding to auth2

## The Wallet Metadata should extend RFC 8414

# presentation definition and dcql_query should be strings


For obtaining and validating client (verifier) metadata.

PresentationDefinition Can Be Sent By Reference
ClientMetadata Can Be Sent By Reference

# VP Formats

# extends oauth requeswt params

# metadata negotiation

The Verifiable Credential and Verifiable Presentation formats supported by the Wallet should be published in its metadata using the metadata parameter vp_formats_supported (see Section 9)****.
# jarm + jarm enc alg default

# static discovery metadata

# parse and validate client identifier + scheme


## Errors

### Mention Dcql 

The Verifier articulates requirements of the Credential(s) that are requested using presentation_definition and presentation_definition_uri parameters that contain a Presentation Definition JSON object as defined in Section 5 of [DIF.PresentationExchange]. Wallet implementations MUST process Presentation Definition JSON object and select candidate Verifiable Credential(s) using the evaluation process described in Section 8 of [DIF.PresentationExchange] unless implementing only a profile of [DIF.PresentationExchange] that provides rules on how to evaluate and process [DIF.PresentationExchange].

### Client Metadata Cannot be sent by reference

This specification enables the Verifier to send both Presentation Definition JSON object and Client Metadata JSON object by value or by reference.

## When is client_metadata requreid.

It is mentioned client metadata is optoinal
However vp_formats is required if not provided otherwise. Does that make client_metadata required?




### End
