import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '../../src/issuer.js';
import {
  base58btcEncode,
  base58btcDecode,
  publicKeyToMultibase,
  multibaseToPublicKey,
  createDIDDocument,
} from '../../src/did/document.js';

describe('base58btcEncode / base58btcDecode', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 255, 128]);
    expect(base58btcDecode(base58btcEncode(bytes))).toEqual(bytes);
  });

  it('preserves leading zero bytes', () => {
    const bytes = new Uint8Array([0, 0, 1, 2]);
    const decoded = base58btcDecode(base58btcEncode(bytes));
    expect(decoded[0]).toBe(0);
    expect(decoded[1]).toBe(0);
    expect(decoded[2]).toBe(1);
    expect(decoded[3]).toBe(2);
  });

  it('encodes a single zero byte as "1"', () => {
    expect(base58btcEncode(new Uint8Array([0]))).toBe('1');
  });
});

describe('publicKeyToMultibase', () => {
  it('returns a string starting with "z"', async () => {
    const kp = await generateKeyPair();
    expect(publicKeyToMultibase(kp.publicKeyBase64)).toMatch(/^z/);
  });

  it('uses only base58btc alphabet characters after the z prefix', async () => {
    const kp = await generateKeyPair();
    const multibase = publicKeyToMultibase(kp.publicKeyBase64);
    expect(multibase.slice(1)).toMatch(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/);
  });

  it('produces consistent output for the same key', async () => {
    const kp = await generateKeyPair();
    expect(publicKeyToMultibase(kp.publicKeyBase64)).toBe(publicKeyToMultibase(kp.publicKeyBase64));
  });
});

describe('multibaseToPublicKey', () => {
  it('round-trips a public key through multibase encoding', async () => {
    const kp = await generateKeyPair();
    const multibase = publicKeyToMultibase(kp.publicKeyBase64);
    expect(multibaseToPublicKey(multibase)).toBe(kp.publicKeyBase64);
  });

  it('throws on a non-z multibase prefix', () => {
    expect(() => multibaseToPublicKey('mSomeBase64Value')).toThrow();
  });

  it('throws on a z-prefixed string that is not an Ed25519 key', () => {
    // Encode bytes without the 0xed 0x01 prefix
    const bogus = 'z' + base58btcEncode(new Uint8Array([0x01, 0x02, 3, 4, 5]));
    expect(() => multibaseToPublicKey(bogus)).toThrow();
  });
});

describe('createDIDDocument', () => {
  it('generates a DID document with correct @context entries', async () => {
    const kp = await generateKeyPair();
    const doc = createDIDDocument('did:web:example.com', kp.publicKeyBase64);
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(doc['@context']).toContain('https://w3id.org/security/suites/ed25519-2020/v1');
  });

  it('sets the id to the given DID', async () => {
    const kp = await generateKeyPair();
    const did = 'did:web:example.com:agents:test-agent';
    const doc = createDIDDocument(did, kp.publicKeyBase64);
    expect(doc.id).toBe(did);
  });

  it('creates a verificationMethod with Ed25519VerificationKey2020 type', async () => {
    const kp = await generateKeyPair();
    const doc = createDIDDocument('did:web:example.com', kp.publicKeyBase64);
    expect(doc.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
  });

  it('includes key-1 reference in authentication and assertionMethod arrays', async () => {
    const kp = await generateKeyPair();
    const did = 'did:web:example.com';
    const doc = createDIDDocument(did, kp.publicKeyBase64);
    expect(doc.authentication).toContain(`${did}#key-1`);
    expect(doc.assertionMethod).toContain(`${did}#key-1`);
  });

  it('sets controller of verificationMethod to the DID', async () => {
    const kp = await generateKeyPair();
    const did = 'did:web:example.com';
    const doc = createDIDDocument(did, kp.publicKeyBase64);
    expect(doc.verificationMethod[0].controller).toBe(did);
  });

  it('embeds the public key as a recoverable multibase in the verificationMethod', async () => {
    const kp = await generateKeyPair();
    const doc = createDIDDocument('did:web:example.com', kp.publicKeyBase64);
    const vm = doc.verificationMethod[0];
    expect(vm.publicKeyMultibase).toMatch(/^z/);
    expect(multibaseToPublicKey(vm.publicKeyMultibase)).toBe(kp.publicKeyBase64);
  });

  it('includes the optional service endpoint when provided', async () => {
    const kp = await generateKeyPair();
    const doc = createDIDDocument('did:web:example.com', kp.publicKeyBase64, 'https://example.com/agent');
    expect(doc.service).toBeDefined();
    expect(doc.service![0].serviceEndpoint).toBe('https://example.com/agent');
  });

  it('omits the service array when no serviceEndpoint is provided', async () => {
    const kp = await generateKeyPair();
    const doc = createDIDDocument('did:web:example.com', kp.publicKeyBase64);
    expect(doc.service).toBeUndefined();
  });
});
