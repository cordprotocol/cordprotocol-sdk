import { v4 as uuidv4 } from 'uuid';
import type { VerifiableCredential } from './types.js';
import type { AgentCredential } from '../credential.js';
import { agentIdToDID, publicKeyFromDIDKey, resolveDID } from './resolver.js';
import { base58btcEncode, base58btcDecode, multibaseToPublicKey } from './document.js';
import { derivePublicKey, publicKeyFromBase64 } from '../crypto/keys.js';
import { activeCryptoBackend } from '../crypto/signatures.js';

function parseExpiry(expiresIn: string): Date {
  if (/^\d{4}-/.test(expiresIn)) {
    const d = new Date(expiresIn);
    if (!isNaN(d.getTime())) return d;
  }
  const match = expiresIn.match(/^(\d+)(m|h|d|w)$/);
  if (!match) {
    throw new Error(
      `Invalid expiresIn: "${expiresIn}". Use "30m", "24h", "7d", "2w", or an ISO 8601 timestamp.`,
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

function sortedJSON(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortedJSON);
  if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.keys(obj as object)
        .sort()
        .map((k) => [k, sortedJSON((obj as Record<string, unknown>)[k])]),
    );
  }
  return obj;
}

function serializeVCPayload(vc: Omit<VerifiableCredential, 'proof'>): string {
  return JSON.stringify(sortedJSON(vc));
}

export async function issueVerifiableCredential(
  params: {
    agentId: string;
    issuedTo: string;
    permissions: string[];
    expiresIn: string;
    attestationHash?: string;
    issuerDID: string;
    domain?: string;
  },
  privateKey: string,
): Promise<VerifiableCredential> {
  const privateKeyBytes = new Uint8Array(Buffer.from(privateKey, 'base64'));
  await derivePublicKey(privateKeyBytes); // validates the key

  const domain = params.domain ?? 'cordprotocol.dev';
  const agentDID = agentIdToDID(params.agentId, domain);
  const issuanceDate = new Date().toISOString();
  const expirationDate = parseExpiry(params.expiresIn).toISOString();

  const vcWithoutProof: Omit<VerifiableCredential, 'proof'> = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'AgentCredential'],
    issuer: params.issuerDID,
    issuanceDate,
    expirationDate,
    credentialSubject: {
      id: agentDID,
      agentId: params.agentId,
      issuedTo: params.issuedTo,
      permissions: [...params.permissions],
      ...(params.attestationHash ? { attestationHash: params.attestationHash } : {}),
    },
  };

  const serialized = serializeVCPayload(vcWithoutProof);
  const msgBytes = new TextEncoder().encode(serialized);
  const sigBytes = await activeCryptoBackend.sign(msgBytes, privateKeyBytes);
  const proofValue = 'z' + base58btcEncode(sigBytes);

  return {
    ...vcWithoutProof,
    proof: {
      type: 'Ed25519Signature2020',
      created: issuanceDate,
      verificationMethod: `${params.issuerDID}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue,
    },
  };
}

export async function verifyVerifiableCredential(vc: VerifiableCredential): Promise<{
  valid: boolean;
  reason?: string;
  agentId?: string;
  permissions?: string[];
}> {
  if (vc.expirationDate && new Date(vc.expirationDate) <= new Date()) {
    return { valid: false, reason: `Credential expired at ${vc.expirationDate}` };
  }

  const vmDID = vc.proof.verificationMethod.split('#')[0];

  let publicKeyBase64: string;
  try {
    if (vmDID.startsWith('did:key:')) {
      publicKeyBase64 = publicKeyFromDIDKey(vmDID);
    } else {
      const resolution = await resolveDID(vmDID);
      if (!resolution.didDocument) {
        return {
          valid: false,
          reason: `Failed to resolve DID: ${resolution.didResolutionMetadata.error}`,
        };
      }
      const vm = resolution.didDocument.verificationMethod.find(
        (m) => m.id === vc.proof.verificationMethod || m.id === `${vmDID}#key-1`,
      );
      if (!vm) {
        return { valid: false, reason: 'Verification method not found in DID document' };
      }
      publicKeyBase64 = multibaseToPublicKey(vm.publicKeyMultibase);
    }
  } catch (err) {
    return { valid: false, reason: `Failed to extract public key: ${(err as Error).message}` };
  }

  const { proof, ...vcWithoutProof } = vc;
  const serialized = serializeVCPayload(vcWithoutProof);
  const msgBytes = new TextEncoder().encode(serialized);

  try {
    if (!proof.proofValue.startsWith('z')) {
      return { valid: false, reason: 'Invalid proofValue encoding (expected base58btc multibase)' };
    }
    const sigBytes = base58btcDecode(proof.proofValue.slice(1));
    const publicKeyBytes = publicKeyFromBase64(publicKeyBase64);
    const valid = await activeCryptoBackend.verify(msgBytes, sigBytes, publicKeyBytes);

    if (!valid) {
      return { valid: false, reason: 'Signature verification failed' };
    }

    return {
      valid: true,
      agentId: vc.credentialSubject.agentId,
      permissions: vc.credentialSubject.permissions,
    };
  } catch (err) {
    return { valid: false, reason: `Signature error: ${(err as Error).message}` };
  }
}

/** Converts an existing AgentCredential to W3C Verifiable Credential format. */
export function agentCredentialToVC(
  credential: AgentCredential,
  issuerDID: string,
  domain?: string,
): VerifiableCredential {
  const agentDID = agentIdToDID(credential.agentId, domain ?? 'cordprotocol.dev');
  const sigBytes = new Uint8Array(Buffer.from(credential.signature, 'base64'));

  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: `urn:uuid:${credential.id}`,
    type: ['VerifiableCredential', 'AgentCredential'],
    issuer: issuerDID,
    issuanceDate: credential.issuedAt,
    expirationDate: credential.expiresAt,
    credentialSubject: {
      id: agentDID,
      agentId: credential.agentId,
      issuedTo: credential.issuedTo,
      permissions: [...credential.permissions],
      attestationHash: credential.attestationHash,
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: credential.issuedAt,
      verificationMethod: `${issuerDID}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: 'z' + base58btcEncode(sigBytes),
    },
  };
}

/** Converts a W3C Verifiable Credential back to a partial AgentCredential shape. */
export function vcToAgentCredential(vc: VerifiableCredential): Partial<AgentCredential> {
  const id = vc.id.startsWith('urn:uuid:') ? vc.id.slice('urn:uuid:'.length) : vc.id;
  const sigBytes = base58btcDecode(vc.proof.proofValue.slice(1));
  const signature = Buffer.from(sigBytes).toString('base64');

  return {
    id,
    agentId: vc.credentialSubject.agentId,
    issuedTo: vc.credentialSubject.issuedTo,
    issuedAt: vc.issuanceDate,
    expiresAt: vc.expirationDate,
    permissions: [...vc.credentialSubject.permissions],
    ...(vc.credentialSubject.attestationHash
      ? { attestationHash: vc.credentialSubject.attestationHash }
      : {}),
    signature,
  };
}
