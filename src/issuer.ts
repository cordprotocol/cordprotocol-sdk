import { v4 as uuidv4 } from 'uuid';
import type { AgentCredential, CredentialPayload, IssueCredentialParams } from './credential.js';
import { serializePayload } from './credential.js';
import { derivePublicKey } from './crypto/keys.js';
import { signMessage, hashSHA256 } from './crypto/signatures.js';
import { validateScopes } from './permissions.js';

export { generateKeyPair } from './crypto/keys.js';
export type { KeyPair } from './crypto/keys.js';

/**
 * Parses a human-friendly expiry string into a future Date.
 *
 * Accepts:
 *   - Duration strings: "30m", "24h", "7d", "2w"
 *   - ISO 8601 timestamps: "2025-12-31T23:59:59.000Z"
 */
function parseExpiry(expiresIn: string): Date {
  // Detect ISO 8601 by leading year digits
  if (/^\d{4}-/.test(expiresIn)) {
    const d = new Date(expiresIn);
    if (!isNaN(d.getTime())) return d;
  }

  const match = expiresIn.match(/^(\d+)(m|h|d|w)$/);
  if (!match) {
    throw new Error(
      `Invalid expiresIn: "${expiresIn}". ` +
        'Use a duration like "30m", "24h", "7d", "2w", or an ISO 8601 timestamp.',
    );
  }

  const msPerUnit: Record<string, number> = {
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 604_800_000,
  };

  return new Date(Date.now() + parseInt(match[1], 10) * msPerUnit[match[2]]);
}

/**
 * Issues a signed AgentCredential.
 *
 * The credential payload is deterministically serialized and signed with the
 * issuer's private key. The corresponding public key is embedded in the
 * credential so verifiers can check the signature without any external lookup.
 *
 * @param params     Credential parameters (agentId, permissions, expiry, etc.)
 * @param privateKey Issuer's private key as a Uint8Array or base64 string
 */
export async function issueCredential(
  params: IssueCredentialParams,
  privateKey: Uint8Array | string,
): Promise<AgentCredential> {
  if (!validateScopes(params.permissions)) {
    throw new Error(
      `Invalid permission scopes: [${params.permissions.join(', ')}]. ` +
        'Each scope must match the format <category>:<resource> using lowercase letters.',
    );
  }

  const privateKeyBytes =
    typeof privateKey === 'string'
      ? new Uint8Array(Buffer.from(privateKey, 'base64'))
      : privateKey;

  const publicKeyBytes = await derivePublicKey(privateKeyBytes);
  const issuerPublicKey = Buffer.from(publicKeyBytes).toString('base64');

  const id = uuidv4();
  const issuedAt = new Date().toISOString();
  const expiresAt = parseExpiry(params.expiresIn ?? '24h').toISOString();
  const attestationHash = hashSHA256(params.attestationData ?? id);

  const payload: CredentialPayload = {
    id,
    agentId: params.agentId,
    issuedTo: params.issuedTo,
    issuedAt,
    expiresAt,
    permissions: [...params.permissions],
    attestationHash,
    issuerPublicKey,
  };

  const signature = await signMessage(serializePayload(payload), privateKeyBytes);

  return { ...payload, signature };
}
