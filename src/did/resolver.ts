import type { DIDDocument, DIDResolutionResult } from './types.js';
import { createDIDDocument, base58btcEncode, base58btcDecode } from './document.js';

export function agentIdToDID(agentId: string, domain: string = 'cordprotocol.dev'): string {
  return `did:web:${domain}:agents:${agentId}`;
}

export function didToAgentId(did: string): string | null {
  const parts = did.split(':');
  if (parts.length < 5) return null;
  if (parts[0] !== 'did' || parts[1] !== 'web') return null;
  if (parts[3] !== 'agents') return null;
  return parts[4] ?? null;
}

/** Converts a base64-encoded Ed25519 public key to a did:key identifier. */
export function publicKeyToDIDKey(publicKeyBase64: string): string {
  const keyBytes = new Uint8Array(Buffer.from(publicKeyBase64, 'base64'));
  const prefixed = new Uint8Array(2 + keyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(keyBytes, 2);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

/** Extracts the base64-encoded Ed25519 public key from a did:key identifier. */
export function publicKeyFromDIDKey(did: string): string {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Not a valid did:key (expected did:key:z...): ${did}`);
  }
  const encoded = did.slice('did:key:z'.length);
  const decoded = base58btcDecode(encoded);
  if (decoded.length < 2 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Not a valid Ed25519 did:key (missing 0xed 0x01 multicodec prefix)');
  }
  return Buffer.from(decoded.slice(2)).toString('base64');
}

function didWebToUrl(did: string): string {
  const withoutPrefix = did.slice('did:web:'.length);
  const parts = withoutPrefix.split(':');
  const domain = parts[0];
  if (parts.length === 1) {
    return `https://${domain}/.well-known/did.json`;
  }
  return `https://${domain}/${parts.slice(1).join('/')}/did.json`;
}

export async function resolveDID(did: string): Promise<DIDResolutionResult> {
  if (did.startsWith('did:key:')) {
    try {
      const publicKeyBase64 = publicKeyFromDIDKey(did);
      const doc = createDIDDocument(did, publicKeyBase64);
      // did:key spec: key fragment is the full multibase key, not "#key-1"
      const keyMultibase = did.slice('did:key:'.length);
      const keyId = `${did}#${keyMultibase}`;
      doc.verificationMethod[0].id = keyId;
      doc.authentication[0] = keyId;
      doc.assertionMethod[0] = keyId;
      return {
        didDocument: doc,
        didResolutionMetadata: { contentType: 'application/did+json' },
        didDocumentMetadata: {},
      };
    } catch (err) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: (err as Error).message },
        didDocumentMetadata: {},
      };
    }
  }

  if (did.startsWith('did:web:')) {
    try {
      const url = didWebToUrl(did);
      const response = await fetch(url);
      if (!response.ok) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: `HTTP ${response.status} fetching ${url}` },
          didDocumentMetadata: {},
        };
      }
      const doc = (await response.json()) as DIDDocument;
      return {
        didDocument: doc,
        didResolutionMetadata: { contentType: 'application/did+json' },
        didDocumentMetadata: {},
      };
    } catch (err) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: (err as Error).message },
        didDocumentMetadata: {},
      };
    }
  }

  return {
    didDocument: null,
    didResolutionMetadata: { error: `Unsupported DID method: ${did}` },
    didDocumentMetadata: {},
  };
}
