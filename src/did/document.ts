import type { DIDDocument } from './types.js';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58btcEncode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) break;
    leadingZeros++;
  }

  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  let encoded = '';
  while (num > 0n) {
    const rem = num % 58n;
    num = num / 58n;
    encoded = BASE58_ALPHABET[Number(rem)] + encoded;
  }

  return '1'.repeat(leadingZeros) + encoded;
}

export function base58btcDecode(str: string): Uint8Array {
  let leadingZeros = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] !== '1') break;
    leadingZeros++;
  }

  let num = BigInt(0);
  for (let i = leadingZeros; i < str.length; i++) {
    const idx = BASE58_ALPHABET.indexOf(str[i]);
    if (idx < 0) throw new Error(`Invalid base58btc character: ${str[i]}`);
    num = num * 58n + BigInt(idx);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}

/** Converts a base64-encoded Ed25519 public key to base58btc multibase format (starts with 'z'). */
export function publicKeyToMultibase(publicKeyBase64: string): string {
  const keyBytes = new Uint8Array(Buffer.from(publicKeyBase64, 'base64'));
  // Ed25519 multicodec varint prefix: [0xED, 0x01]
  const prefixed = new Uint8Array(2 + keyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(keyBytes, 2);
  return 'z' + base58btcEncode(prefixed);
}

/** Converts a base58btc multibase-encoded key back to base64. */
export function multibaseToPublicKey(multibase: string): string {
  if (!multibase.startsWith('z')) {
    throw new Error('Expected base58btc multibase encoding (must start with "z")');
  }
  const decoded = base58btcDecode(multibase.slice(1));
  if (decoded.length < 2 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Not a valid Ed25519 multibase key (missing 0xed 0x01 prefix)');
  }
  return Buffer.from(decoded.slice(2)).toString('base64');
}

export function createDIDDocument(
  did: string,
  publicKey: string,
  serviceEndpoint?: string,
): DIDDocument {
  const keyId = `${did}#key-1`;
  const doc: DIDDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: publicKeyToMultibase(publicKey),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };

  if (serviceEndpoint) {
    doc.service = [
      {
        id: `${did}#cord-service`,
        type: 'CordProtocolService',
        serviceEndpoint,
      },
    ];
  }

  return doc;
}
