// Types and utilities
export type {
  AgentCredential,
  CredentialPayload,
  IssueCredentialParams,
  VerificationResult,
} from './credential.js';
export { serializePayload } from './credential.js';

// Issuance
export { generateKeyPair, issueCredential } from './issuer.js';
export type { KeyPair } from './issuer.js';

// Verification
export {
  verifyCredential,
  isExpired,
  hasPermission,
  validateCredentialSchema,
} from './verifier.js';

// Permissions
export { SCOPES, validateScopes, parseSpendLimit } from './permissions.js';
export type { StandardScope } from './permissions.js';

// Crypto internals — exposed for advanced use (e.g. custom backends)
export { activeCryptoBackend, hashSHA256 } from './crypto/signatures.js';
export type { CryptoBackend } from './crypto/signatures.js';

// Hosted API client
export { CordProtocol } from './client.js';
export type { CordProtocolConfig, AgentRegistration } from './client.js';

// Standalone registry functions
export {
  registerAgent,
  lookupAgent,
  checkRevocationStatus,
  revokeCredential,
} from './registry.js';

// W3C DID & Verifiable Credentials
export type {
  DIDDocument,
  VerificationMethod,
  ServiceEndpoint,
  VerifiableCredential,
  DIDResolutionResult,
} from './did/types.js';
export {
  base58btcEncode,
  base58btcDecode,
  publicKeyToMultibase,
  multibaseToPublicKey,
  createDIDDocument,
} from './did/document.js';
export {
  agentIdToDID,
  didToAgentId,
  resolveDID,
  publicKeyToDIDKey,
  publicKeyFromDIDKey,
} from './did/resolver.js';
export {
  issueVerifiableCredential,
  verifyVerifiableCredential,
  agentCredentialToVC,
  vcToAgentCredential,
} from './did/vc.js';
