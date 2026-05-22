/**
 * basic-verify.ts — Minimal example: verify a credential and check permissions.
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
} from '../src/index.js';

// Set up: issue a credential to verify (normally this comes from elsewhere)
const keyPair = await generateKeyPair();
const credential = await issueCredential(
  {
    agentId: 'data-agent',
    issuedTo: 'Jane Doe',
    permissions: ['read:data', 'communicate:api'],
    expiresIn: '1h',
  },
  keyPair.privateKeyBase64,
);

// Encode for transport
const encoded = Buffer.from(JSON.stringify(credential)).toString('base64');

// ─── Verification (as a resource server would do it) ──────────────────────────

// verifyCredential accepts the credential object OR the base64 string
const result = await verifyCredential(encoded);

if (!result.valid) {
  console.error('Access denied:', result.errors);
  process.exit(1);
}

const verified = result.credential!;
console.log('Credential is VALID');
console.log(`Agent: ${verified.agentId} (owned by ${verified.issuedTo})`);
console.log(`Expires: ${verified.expiresAt}`);

// ─── Permission gating ────────────────────────────────────────────────────────

console.log('\nPermission checks:');
console.log('  read:data      ->', hasPermission(verified, 'read:data'));      // true
console.log('  communicate:api ->', hasPermission(verified, 'communicate:api')); // true
console.log('  execute:code   ->', hasPermission(verified, 'execute:code'));   // false

console.log('\nExpired?', isExpired(verified)); // false
