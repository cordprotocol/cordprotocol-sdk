import { signAsync, verifyAsync } from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Algorithm-agnostic cryptographic signing backend.
 *
 * POST-QUANTUM SWAP PATH:
 * To upgrade to CRYSTALS-Dilithium3 / ML-DSA (FIPS 204):
 *   1. Implement this interface with a Dilithium library
 *      (e.g. @noble/post-quantum when production-ready)
 *   2. Replace `activeCryptoBackend` with your implementation
 *   3. Update `derivePublicKey` in crypto/keys.ts
 *
 * No changes to issuer.ts, verifier.ts, or any SDK consumer are required.
 * Key and signature byte sizes will change, but base64 encoding absorbs
 * that transparently. Existing Ed25519 credentials will no longer verify
 * against a Dilithium backend, so plan a credential rotation strategy.
 */
export interface CryptoBackend {
  /** Human-readable algorithm identifier embedded in no credentials but useful for logging */
  readonly algorithmId: string;
  sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
}

const ed25519Backend: CryptoBackend = {
  algorithmId: 'Ed25519',

  sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    return signAsync(message, privateKey);
  },

  // noble/ed25519 verifyAsync signature: (sig, msg, pubKey)
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return verifyAsync(signature, message, publicKey);
  },
};

/** The active signing backend. Swap this reference to change the algorithm globally. */
export const activeCryptoBackend: CryptoBackend = ed25519Backend;

/**
 * Signs a UTF-8 message string, returning a base64-encoded signature.
 */
export async function signMessage(message: string, privateKey: Uint8Array): Promise<string> {
  const bytes = new TextEncoder().encode(message);
  const sig = await activeCryptoBackend.sign(bytes, privateKey);
  return Buffer.from(sig).toString('base64');
}

/**
 * Verifies a base64-encoded signature over a UTF-8 message.
 * Returns true only if the signature is cryptographically valid.
 */
export async function verifyMessage(
  message: string,
  signatureBase64: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  const bytes = new TextEncoder().encode(message);
  const sig = new Uint8Array(Buffer.from(signatureBase64, 'base64'));
  return activeCryptoBackend.verify(bytes, sig, publicKey);
}

/**
 * Returns a base64-encoded SHA-256 hash of the input string.
 * Used for attestation hashes over agent config or code bundles.
 */
export function hashSHA256(data: string): string {
  const bytes = new TextEncoder().encode(data);
  return Buffer.from(sha256(bytes)).toString('base64');
}
