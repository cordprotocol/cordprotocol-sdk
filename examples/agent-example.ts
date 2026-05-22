/**
 * agent-example.ts — Full walkthrough of the Cord Protocol identity lifecycle.
 *
 * Demonstrates:
 *   1. Key pair generation (one-time issuer setup)
 *   2. Issuing a credential with code attestation
 *   3. Transporting the credential as a base64 string
 *   4. Verifying at the resource server — no network call needed
 *   5. Permission gating before granting access
 *   6. Detecting tampered credentials
 *   7. Revoking access by checking expiry
 *
 * In your project, replace the relative import with:
 *   import { ... } from '@cordprotocol/sdk';
 */

import {
  generateKeyPair,
  issueCredential,
  verifyCredential,
  hasPermission,
  isExpired,
  SCOPES,
  parseSpendLimit,
} from '../src/index.js';

// ─── 1. Issuer setup ──────────────────────────────────────────────────────────
// Generate once; store the key pair in a secrets manager (Vault, AWS Secrets, etc.)

const issuerKeyPair = await generateKeyPair();
console.log('=== Issuer Setup ===');
console.log(`Algorithm:  Ed25519 (post-quantum swap path: CRYSTALS-Dilithium)`);
console.log(`Public Key: ${issuerKeyPair.publicKeyBase64.slice(0, 20)}...`);

// ─── 2. Issue a credential ────────────────────────────────────────────────────
// Typically done by an orchestration service when a new agent is deployed.

// Hash the agent's config for tamper-evident attestation.
// Any change to the deployed config will produce a different hash.
const agentConfig = JSON.stringify({
  model: 'claude-sonnet-4-6',
  version: '3.0.1',
  entrypoint: 'dist/agent.js',
  checksum: 'sha256:e3b0c44298fc1c149afb',
});

const credential = await issueCredential(
  {
    agentId: 'customer-support-bot',
    issuedTo: 'Acme Corp',
    permissions: [
      SCOPES.READ_DATA,
      SCOPES.WRITE_MESSAGES,
      SCOPES.COMMUNICATE_API,
      'spend:100', // custom spend limit
    ],
    expiresIn: '8h', // short-lived credentials limit blast radius
    attestationData: agentConfig,
  },
  issuerKeyPair.privateKeyBase64,
);

console.log('\n=== Credential Issued ===');
console.log(`ID:          ${credential.id}`);
console.log(`Agent:       ${credential.agentId}`);
console.log(`Owner:       ${credential.issuedTo}`);
console.log(`Permissions: ${credential.permissions.join(', ')}`);
console.log(`Expires:     ${credential.expiresAt}`);

// ─── 3. Transport ─────────────────────────────────────────────────────────────
// Credentials are opaque base64 strings — pass them in HTTP headers,
// message queues, database columns, or any string field.

const transportToken = Buffer.from(JSON.stringify(credential)).toString('base64');
console.log(`\nTransport token length: ${transportToken.length} chars`);

// ─── 4. Verification at the resource server ───────────────────────────────────
// Any service that receives the token can verify it independently.
// No issuer server call required — the public key is inside the token.

console.log('\n=== Verification ===');
const result = await verifyCredential(transportToken);

if (!result.valid) {
  console.error('Access DENIED:', result.errors);
  process.exit(1);
}

const agent = result.credential!;
console.log('Credential: VALID');
console.log(`Issued to:  ${agent.issuedTo}`);

// ─── 5. Permission gating ─────────────────────────────────────────────────────

console.log('\n=== Permission Checks ===');

function gate(scope: string): void {
  const granted = hasPermission(agent, scope);
  console.log(`  ${granted ? '✓' : '✗'} ${scope}`);
}

gate(SCOPES.READ_DATA);       // ✓
gate(SCOPES.WRITE_MESSAGES);  // ✓
gate(SCOPES.COMMUNICATE_API); // ✓
gate(SCOPES.EXECUTE_CODE);    // ✗ — not granted
gate('spend:100');            // ✓
gate('spend:50000');          // ✗ — amount not in credentials

// Parse spend limits for financial controls
const spendScope = agent.permissions.find((p) => p.startsWith('spend:'));
if (spendScope) {
  const limit = parseSpendLimit(spendScope);
  console.log(`\n  Spend limit: $${limit}`);
}

// ─── 6. Tamper detection ──────────────────────────────────────────────────────

console.log('\n=== Tamper Detection ===');

// Attempt to escalate privileges by modifying the credential
const tampered = {
  ...agent,
  permissions: [...agent.permissions, SCOPES.EXECUTE_CODE],
};

const tamperedResult = await verifyCredential(tampered);
console.log(`Tampered credential valid? ${tamperedResult.valid}`);
console.log(`Error: ${tamperedResult.errors[0]}`);

// ─── 7. Expiry ────────────────────────────────────────────────────────────────

console.log('\n=== Expiry Check ===');
console.log(`Is expired? ${isExpired(agent)}`);
console.log(`Expires at: ${new Date(agent.expiresAt).toLocaleString()}`);
console.log('\nDone.');
