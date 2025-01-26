export function parseIfJson<T>(input: T): T | Record<string, unknown> {
  if (typeof input !== 'string') {
    return input
  }

  try {
    // Try to parse the string as JSON
    return JSON.parse(input)
  } catch (error) {}

  return input
}
