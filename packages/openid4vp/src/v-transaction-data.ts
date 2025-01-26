import * as v from 'valibot'

export const vTransactionData = v.object({
  type: v.string(),
  credential_ids: v.pipe(v.array(v.string()), v.nonEmpty()),
  transaction_data_hashes_alg: v.optional(v.array(v.string())),
})
export type TransactionData = v.InferOutput<typeof vTransactionData>
