/**
 * AgentCredential — the core identity document for an AI agent.
 *
 * A credential is a signed JSON object issued by an authority and verifiable
 * by any party that has the issuer's public key. No server call is required
 * for verification — the signature is self-contained.
 */

/** A fully signed agent identity credential. */
export interface AgentCredential {
  /** UUID v4 — unique credential identifier */
  id: string;
  /** Identifier for the agent this credential belongs to */
  agentId: string;
  /** Human or organization that owns/operates this agent */
  issuedTo: string;
  /** ISO 8601 timestamp of issuance */
  issuedAt: string;
  /** ISO 8601 timestamp of expiry */
  expiresAt: string;
  /** Permission scopes granted to this agent (e.g. ["read:data", "spend:500"]) */
  permissions: string[];
  /** Base64-encoded SHA-256 hash of the agent's config or code for tamper-evident attestation */
  attestationHash: string;
  /** Base64-encoded public key of the issuing authority */
  issuerPublicKey: string;
  /** Base64-encoded signature over the credential payload (all fields except this one) */
  signature: string;
}

/** Unsigned credential payload — everything a credential contains before signing. */
export type CredentialPayload = Omit<AgentCredential, 'signature'>;

/** Input parameters for issuing a new credential. */
export interface IssueCredentialParams {
  /** Identifier for the agent */
  agentId: string;
  /** Human or organization name that owns this agent */
  issuedTo: string;
  /** Permission scopes to grant (must match format <category>:<resource>) */
  permissions: string[];
  /**
   * How long until this credential expires.
   * Accepts duration strings ("30m", "24h", "7d", "2w") or an ISO 8601 timestamp.
   * Defaults to "24h" if omitted.
   */
  expiresIn?: string;
  /**
   * Arbitrary string to hash for the attestation field — typically a JSON
   * serialization of the agent's config or a hash of its code bundle.
   * If omitted, the credential ID is used (still unique, just not code-bound).
   */
  attestationData?: string;
}

/** Returned by verifyCredential() with a verdict and any error messages. */
export interface VerificationResult {
  /** True only when schema, expiry, AND signature are all valid. */
  valid: boolean;
  /** Human-readable error descriptions. Empty when valid is true. */
  errors: string[];
  /** The parsed credential if it was structurally valid (present even when invalid). */
  credential?: AgentCredential;
}

/**
 * Deterministically serializes a credential payload for signing and verification.
 *
 * Property keys are sorted alphabetically so the output is identical regardless
 * of the insertion order of properties in the object — which can differ between
 * JS engines, destructuring patterns, and JSON.parse implementations.
 */
export function serializePayload(payload: CredentialPayload): string {
  const sortedKeys = (Object.keys(payload) as Array<keyof CredentialPayload>).sort();
  return JSON.stringify(payload, sortedKeys);
}
