import { Oauth2Error } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { JarmAuthResponse, type JarmAuthResponseEncryptedOnly } from './m-jarm-auth-response.js'

export const jarmAuthResponseValidate = (input: {
  auth_request: { client_id: string }
  auth_response: JarmAuthResponse | JarmAuthResponseEncryptedOnly
}) => {
  const { auth_request, auth_response } = input

  // The traditional Jarm Validation Methods do not account for the encrypted response.
  if (!v.is(JarmAuthResponse, auth_response)) {
    return
  }

  // 3. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (auth_request.client_id !== auth_response.aud) {
    throw new Oauth2Error(
      `Invalid audience in jarm-auth-response. Expected '${
        auth_request.client_id
      }' received '${JSON.stringify(auth_response.aud)}'.`
    )
  }

  // 4. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // 120 seconds clock skew
  if (auth_response.exp && auth_response.exp < Date.now() / 1000) {
    throw new Oauth2Error('Jarm auth response is expired.')
  }
}
