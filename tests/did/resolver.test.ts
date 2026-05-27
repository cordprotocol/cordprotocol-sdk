import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { generateKeyPair } from '../../src/issuer.js';
import {
  agentIdToDID,
  didToAgentId,
  resolveDID,
  publicKeyToDIDKey,
  publicKeyFromDIDKey,
} from '../../src/did/resolver.js';
import { createDIDDocument } from '../../src/did/document.js';

describe('agentIdToDID', () => {
  it('generates a did:web identifier with the default domain', () => {
    expect(agentIdToDID('trading-agent')).toBe('did:web:cordprotocol.dev:agents:trading-agent');
  });

  it('uses a custom domain when provided', () => {
    expect(agentIdToDID('my-agent', 'example.com')).toBe('did:web:example.com:agents:my-agent');
  });

  it('handles agent IDs with hyphens and numbers', () => {
    expect(agentIdToDID('order-bot-v2')).toBe('did:web:cordprotocol.dev:agents:order-bot-v2');
  });
});

describe('didToAgentId', () => {
  it('extracts agentId from a cordprotocol.dev did:web DID', () => {
    expect(didToAgentId('did:web:cordprotocol.dev:agents:trading-agent')).toBe('trading-agent');
  });

  it('extracts agentId from a custom domain did:web DID', () => {
    expect(didToAgentId('did:web:example.com:agents:my-bot')).toBe('my-bot');
  });

  it('returns null for a did:key (not a web DID)', () => {
    expect(didToAgentId('did:key:z6MkhaXgBZDvotDkL5257faiz')).toBeNull();
  });

  it('returns null when the path segment is not "agents"', () => {
    expect(didToAgentId('did:web:example.com:users:alice')).toBeNull();
  });

  it('returns null for a bare did:web without path', () => {
    expect(didToAgentId('did:web:example.com')).toBeNull();
  });
});

describe('publicKeyToDIDKey / publicKeyFromDIDKey', () => {
  it('converts a public key to a did:key identifier starting with did:key:z', async () => {
    const kp = await generateKeyPair();
    const did = publicKeyToDIDKey(kp.publicKeyBase64);
    expect(did).toMatch(/^did:key:z/);
  });

  it('round-trips a public key through DID key encoding', async () => {
    const kp = await generateKeyPair();
    const did = publicKeyToDIDKey(kp.publicKeyBase64);
    expect(publicKeyFromDIDKey(did)).toBe(kp.publicKeyBase64);
  });

  it('produces different DIDs for different key pairs', async () => {
    const [kp1, kp2] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    expect(publicKeyToDIDKey(kp1.publicKeyBase64)).not.toBe(publicKeyToDIDKey(kp2.publicKeyBase64));
  });

  it('throws publicKeyFromDIDKey on a non-did:key string', () => {
    expect(() => publicKeyFromDIDKey('did:web:example.com')).toThrow();
  });
});

describe('resolveDID — did:key', () => {
  it('resolves a did:key to a DID document with the correct id', async () => {
    const kp = await generateKeyPair();
    const did = publicKeyToDIDKey(kp.publicKeyBase64);
    const result = await resolveDID(did);
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
  });

  it('includes no resolution error for a valid did:key', async () => {
    const kp = await generateKeyPair();
    const did = publicKeyToDIDKey(kp.publicKeyBase64);
    const result = await resolveDID(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  it('returns an error and null document for an invalid did:key', async () => {
    const result = await resolveDID('did:key:zinvalid!!!');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBeTruthy();
  });
});

describe('resolveDID — unsupported method', () => {
  it('returns an error for an unsupported DID method', async () => {
    const result = await resolveDID('did:ethr:0x1234');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('Unsupported');
  });
});

describe('resolveDID — did:web', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('resolves a did:web by fetching the DID document URL', async () => {
    const kp = await generateKeyPair();
    const did = 'did:web:example.com:agents:test-agent';
    const mockDoc = createDIDDocument(did, kp.publicKeyBase64);

    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockDoc),
    });

    const result = await resolveDID(did);
    expect(result.didDocument).toEqual(mockDoc);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  it('returns an error when the did:web fetch returns a non-ok status', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 404,
    });

    const result = await resolveDID('did:web:example.com:agents:nonexistent');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('404');
  });

  it('returns an error when fetch throws (network error)', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network failure'));

    const result = await resolveDID('did:web:example.com:agents:my-agent');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('network failure');
  });
});
