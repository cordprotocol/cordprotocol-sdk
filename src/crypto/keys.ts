import { getPublicKeyAsync, utils } from '@noble/ed25519';

export interface KeyPair {
  /** Raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** Raw 32-byte Ed25519 private key — keep secret */
  privateKey: Uint8Array;
  /** Base64-encoded public key, embedded in issued credentials */
  publicKeyBase64: string;
  /** Base64-encoded private key, used to sign credentials */
  privateKeyBase64: string;
}

/**
 * Generates a new Ed25519 key pair using a cryptographically secure RNG.
 *
 * POST-QUANTUM UPGRADE PATH:
 * When CRYSTALS-Dilithium (ML-DSA / FIPS 204) reaches production-grade JS
 * support (e.g. via @noble/post-quantum), replace this function and
 * `derivePublicKey` below with Dilithium equivalents. The `KeyPair` interface
 * is algorithm-agnostic — no callers need to change.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = utils.randomPrivateKey();
  const publicKey = await getPublicKeyAsync(privateKey);

  return {
    privateKey,
    publicKey,
    publicKeyBase64: Buffer.from(publicKey).toString('base64'),
    privateKeyBase64: Buffer.from(privateKey).toString('base64'),
  };
}

/**
 * Derives the public key from a private key.
 * This is algorithm-specific — swap with the Dilithium equivalent when upgrading.
 */
export async function derivePublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  return getPublicKeyAsync(privateKey);
}

export function publicKeyFromBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

export function privateKeyFromBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}
