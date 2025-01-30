import { Oauth2Error } from '@openid4vc/oauth2'
import { decodeBase64, encodeToUtf8String } from '@openid4vc/utils'
import * as v from 'valibot'
import { parseIfJson } from '../parse-raw-json'
import { type TransactionData, vTransactionData } from './v-transaction-data.js'

export function parseTransactionData(transactionData: string[]): TransactionData {
  const decoded = transactionData.map((td) => parseIfJson(encodeToUtf8String(decodeBase64(td))))
  const parsed = v.safeParse(vTransactionData, decoded)

  if (!parsed.success) {
    throw new Oauth2Error('Invalid transaction data.')
  }

  return parsed.output
}
