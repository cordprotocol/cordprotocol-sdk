import { describe, expect, it } from 'vitest';
import { generateKeyPair, issueCredential } from '../../src/issuer.js';
import {
  issueVerifiableCredential,
  verifyVerifiableCredential,
  agentCredentialToVC,
  vcToAgentCredential,
} from '../../src/did/vc.js';
import { publicKeyToDIDKey } from '../../src/did/resolver.js';

async function freshIssuer() {
  const kp = await generateKeyPair();
  const issuerDID = publicKeyToDIDKey(kp.publicKeyBase64);
  return { kp, issuerDID };
}

describe('issueVerifiableCredential', () => {
  it('returns a VC with the W3C credentials @context', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'test-agent', issuedTo: 'Acme', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
  });

  it('sets issuer to the provided issuerDID', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'test-agent', issuedTo: 'Acme', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    expect(vc.issuer).toBe(issuerDID);
  });

  it('encodes the agentId as did:web in credentialSubject.id', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      {
        agentId: 'trading-agent',
        issuedTo: 'Acme',
        permissions: ['read:data'],
        expiresIn: '24h',
        issuerDID,
        domain: 'example.com',
      },
      kp.privateKeyBase64,
    );
    expect(vc.credentialSubject.id).toBe('did:web:example.com:agents:trading-agent');
  });

  it('copies the permissions into credentialSubject', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data', 'write:orders'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    expect(vc.credentialSubject.permissions).toEqual(['read:data', 'write:orders']);
  });

  it('includes an Ed25519Signature2020 proof with a z-prefixed proofValue', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof.proofValue).toMatch(/^z/);
    expect(vc.proof.proofPurpose).toBe('assertionMethod');
  });

  it('sets the id as a urn:uuid URI', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    expect(vc.id).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });
});

describe('verifyVerifiableCredential', () => {
  it('verifies a freshly issued VC with a did:key issuer', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'test-agent', issuedTo: 'Acme', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    const result = await verifyVerifiableCredential(vc);
    expect(result.valid).toBe(true);
    expect(result.agentId).toBe('test-agent');
    expect(result.permissions).toEqual(['read:data']);
  });

  it('returns the permission list on a valid VC', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      {
        agentId: 'agent',
        issuedTo: 'Corp',
        permissions: ['read:data', 'write:orders', 'spend:500'],
        expiresIn: '24h',
        issuerDID,
      },
      kp.privateKeyBase64,
    );
    const result = await verifyVerifiableCredential(vc);
    expect(result.valid).toBe(true);
    expect(result.permissions).toEqual(['read:data', 'write:orders', 'spend:500']);
  });

  it('fails verification for an expired VC', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    vc.expirationDate = new Date(Date.now() - 1000).toISOString();
    const result = await verifyVerifiableCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  it('fails verification when a permission is tampered with', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    vc.credentialSubject.permissions = ['write:admin'];
    const result = await verifyVerifiableCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Signature');
  });

  it('fails verification when the proofValue is tampered', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    vc.proof.proofValue = 'z' + 'A'.repeat(86);
    const result = await verifyVerifiableCredential(vc);
    expect(result.valid).toBe(false);
  });

  it('fails verification when the agentId is tampered', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'original-agent', issuedTo: 'Corp', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    vc.credentialSubject.agentId = 'different-agent';
    const result = await verifyVerifiableCredential(vc);
    expect(result.valid).toBe(false);
  });
});

describe('agentCredentialToVC', () => {
  it('converts an AgentCredential to VC format with correct type array', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'bot-1', issuedTo: 'Acme Corp', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    const issuerDID = publicKeyToDIDKey(kp.publicKeyBase64);
    const vc = agentCredentialToVC(credential, issuerDID);
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain('AgentCredential');
  });

  it('maps issuer DID correctly', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'bot-1', issuedTo: 'Acme Corp', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    const issuerDID = publicKeyToDIDKey(kp.publicKeyBase64);
    const vc = agentCredentialToVC(credential, issuerDID);
    expect(vc.issuer).toBe(issuerDID);
  });

  it('maps credentialSubject fields from the credential', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'bot-1', issuedTo: 'Acme Corp', permissions: ['read:data', 'write:orders'] },
      kp.privateKeyBase64,
    );
    const vc = agentCredentialToVC(credential, 'did:web:example.com');
    expect(vc.credentialSubject.agentId).toBe('bot-1');
    expect(vc.credentialSubject.issuedTo).toBe('Acme Corp');
    expect(vc.credentialSubject.permissions).toEqual(['read:data', 'write:orders']);
  });

  it('maps issuedAt and expiresAt to issuanceDate and expirationDate', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'bot-1', issuedTo: 'Acme Corp', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    const vc = agentCredentialToVC(credential, 'did:web:example.com');
    expect(vc.issuanceDate).toBe(credential.issuedAt);
    expect(vc.expirationDate).toBe(credential.expiresAt);
  });

  it('encodes the credential id as urn:uuid in vc.id', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'bot-1', issuedTo: 'Acme Corp', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    const vc = agentCredentialToVC(credential, 'did:web:example.com');
    expect(vc.id).toBe(`urn:uuid:${credential.id}`);
  });

  it('encodes agentId as did:web using the supplied domain', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'my-agent', issuedTo: 'Acme Corp', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    const vc = agentCredentialToVC(credential, 'did:web:example.com', 'example.com');
    expect(vc.credentialSubject.id).toBe('did:web:example.com:agents:my-agent');
  });
});

describe('vcToAgentCredential', () => {
  it('converts a VC back to a partial AgentCredential with correct fields', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'test-agent', issuedTo: 'Acme Corp', permissions: ['read:data', 'write:orders'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    const partial = vcToAgentCredential(vc);
    expect(partial.agentId).toBe('test-agent');
    expect(partial.issuedTo).toBe('Acme Corp');
    expect(partial.permissions).toEqual(['read:data', 'write:orders']);
  });

  it('extracts the UUID from the urn:uuid id', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'test-agent', issuedTo: 'Acme Corp', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    const partial = vcToAgentCredential(vc);
    expect(partial.id).not.toContain('urn:uuid:');
    expect(partial.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('maps issuanceDate and expirationDate back to issuedAt and expiresAt', async () => {
    const { kp, issuerDID } = await freshIssuer();
    const vc = await issueVerifiableCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '24h', issuerDID },
      kp.privateKeyBase64,
    );
    const partial = vcToAgentCredential(vc);
    expect(partial.issuedAt).toBe(vc.issuanceDate);
    expect(partial.expiresAt).toBe(vc.expirationDate);
  });

  it('round-trips agentCredentialToVC → vcToAgentCredential and preserves key fields', async () => {
    const kp = await generateKeyPair();
    const credential = await issueCredential(
      { agentId: 'roundtrip-agent', issuedTo: 'Corp', permissions: ['read:data', 'spend:100'] },
      kp.privateKeyBase64,
    );
    const issuerDID = publicKeyToDIDKey(kp.publicKeyBase64);
    const vc = agentCredentialToVC(credential, issuerDID);
    const partial = vcToAgentCredential(vc);
    expect(partial.agentId).toBe(credential.agentId);
    expect(partial.issuedTo).toBe(credential.issuedTo);
    expect(partial.permissions).toEqual(credential.permissions);
    expect(partial.id).toBe(credential.id);
  });
});
