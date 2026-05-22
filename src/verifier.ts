import type { AgentCredential, VerificationResult } from './credential.js';
import { serializePayload } from './credential.js';
import { publicKeyFromBase64 } from './crypto/keys.js';
import { verifyMessage } from './crypto/signatures.js';

/**
 * Returns true if the credential's expiry timestamp is in the past.
 * Does not check the signature — use verifyCredential() for full validation.
 */
export function isExpired(credential: AgentCredential): boolean {
  return new Date(credential.expiresAt) <= new Date();
}

/**
 * Returns true if the credential contains the given permission scope.
 * Exact string match — does not handle wildcard or hierarchical scopes.
 */
export function hasPermission(credential: AgentCredential, scope: string): boolean {
  return credential.permissions.includes(scope);
}

/**
 * Validates the structural schema of an unknown value as a potential credential.
 * Returns an array of error messages; an empty array means the schema is valid.
 */
export function validateCredentialSchema(candidate: unknown): string[] {
  const errors: string[] = [];

  if (typeof candidate !== 'object' || candidate === null) {
    return ['Credential must be a non-null object'];
  }

  const c = candidate as Record<string, unknown>;

  const requiredStringFields = [
    'id',
    'agentId',
    'issuedTo',
    'issuedAt',
    'expiresAt',
    'attestationHash',
    'issuerPublicKey',
    'signature',
  ];

  for (const field of requiredStringFields) {
    if (typeof c[field] !== 'string' || (c[field] as string).length === 0) {
      errors.push(`Missing or empty required field: "${field}"`);
    }
  }

  if (!Array.isArray(c.permissions)) {
    errors.push('"permissions" must be an array');
  } else if ((c.permissions as unknown[]).some((p) => typeof p !== 'string')) {
    errors.push('"permissions" must contain only strings');
  }

  // Validate timestamps are parseable
  if (typeof c.issuedAt === 'string' && isNaN(Date.parse(c.issuedAt))) {
    errors.push('"issuedAt" is not a valid date');
  }
  if (typeof c.expiresAt === 'string' && isNaN(Date.parse(c.expiresAt))) {
    errors.push('"expiresAt" is not a valid date');
  }

  return errors;
}

/**
 * Fully verifies an AgentCredential: schema validity, expiry, and signature.
 *
 * Accepts either a parsed AgentCredential object or a base64-encoded JSON string
 * (as produced by `Buffer.from(JSON.stringify(credential)).toString('base64')`).
 *
 * The signature check reconstructs the exact serialized payload that was signed
 * at issuance. Any modification to any field — including permissions, expiry,
 * agentId, etc. — will cause the signature check to fail.
 *
 * @returns VerificationResult with a `valid` flag and descriptive errors
 */
export async function verifyCredential(
  credentialOrBase64: AgentCredential | string,
): Promise<VerificationResult> {
  let credential: AgentCredential;

  if (typeof credentialOrBase64 === 'string') {
    try {
      const json = Buffer.from(credentialOrBase64, 'base64').toString('utf-8');
      credential = JSON.parse(json) as AgentCredential;
    } catch {
      return {
        valid: false,
        errors: ['Failed to decode credential: must be a base64-encoded JSON string'],
      };
    }
  } else {
    credential = credentialOrBase64;
  }

  const schemaErrors = validateCredentialSchema(credential);
  if (schemaErrors.length > 0) {
    return { valid: false, errors: schemaErrors, credential };
  }

  const errors: string[] = [];

  if (isExpired(credential)) {
    errors.push(`Credential expired at ${credential.expiresAt}`);
  }

  try {
    const { signature, ...payload } = credential;
    const serialized = serializePayload(payload);
    const publicKey = publicKeyFromBase64(credential.issuerPublicKey);
    const signatureValid = await verifyMessage(serialized, signature, publicKey);

    if (!signatureValid) {
      errors.push(
        'Signature verification failed — credential may have been tampered with',
      );
    }
  } catch (err) {
    errors.push(`Signature error: ${(err as Error).message}`);
  }

  return { valid: errors.length === 0, errors, credential };
}
