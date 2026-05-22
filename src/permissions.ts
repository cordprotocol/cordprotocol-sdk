/**
 * Permission scope constants and utilities.
 *
 * Scopes follow the format: <category>:<resource_or_limit>
 * The standard scopes below cover common agent use-cases. Applications are
 * free to define custom scopes — any string matching the format is accepted.
 */

export const SCOPES = {
  // Read
  READ_DATA: 'read:data',
  READ_MEMORY: 'read:memory',
  READ_CONTEXT: 'read:context',

  // Write
  WRITE_DATA: 'write:data',
  WRITE_ORDERS: 'write:orders',
  WRITE_MESSAGES: 'write:messages',

  // Execution
  EXECUTE_CODE: 'execute:code',
  EXECUTE_TOOLS: 'execute:tools',

  // Communication
  COMMUNICATE_EMAIL: 'communicate:email',
  COMMUNICATE_API: 'communicate:api',
  COMMUNICATE_WEBHOOK: 'communicate:webhook',
} as const;

export type StandardScope = (typeof SCOPES)[keyof typeof SCOPES];

/** Valid scope format: lowercase-word : lowercase-word-or-number */
const SCOPE_PATTERN = /^[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9_:.-]*$/;

/**
 * Returns true if every scope in the array is well-formed.
 * Rejects empty arrays and any scope that doesn't match <word>:<word_or_number>.
 */
export function validateScopes(scopes: string[]): boolean {
  if (!Array.isArray(scopes) || scopes.length === 0) return false;
  return scopes.every((s) => SCOPE_PATTERN.test(s));
}

/**
 * Parses a spend scope and returns the numeric limit, or null if not a spend scope.
 * "spend:500" → 500, "spend:99.99" → 99.99, "read:data" → null
 */
export function parseSpendLimit(scope: string): number | null {
  const match = scope.match(/^spend:(\d+(?:\.\d+)?)$/);
  return match ? parseFloat(match[1]) : null;
}
