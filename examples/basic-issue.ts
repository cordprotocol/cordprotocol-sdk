/**
 * basic-issue.ts — Minimal example: generate a key pair and issue a credential.
 *
 * In your project, replace the relative import with:
 *   import { generateKeyPair, issueCredential } from '@cordprotocol/sdk';
 */

import { generateKeyPair, issueCredential } from '../src/index.js';

// 1. Generate an issuer key pair. In production, generate once and store securely.
const keyPair = await generateKeyPair();
console.log('Issuer public key:', keyPair.publicKeyBase64);

// 2. Issue a credential for an agent.
const credential = await issueCredential(
  {
    agentId: 'order-bot-v1',
    issuedTo: 'Acme Corp',
    permissions: ['read:data', 'write:orders', 'spend:500'],
    expiresIn: '24h',
    attestationData: JSON.stringify({ model: 'gpt-4o', version: '2.1.0' }),
  },
  keyPair.privateKeyBase64,
);

console.log('\nIssued credential:');
console.log(JSON.stringify(credential, null, 2));

// 3. Encode for transport (HTTP header, database field, etc.)
const encoded = Buffer.from(JSON.stringify(credential)).toString('base64');
console.log('\nBase64 for transport:');
console.log(encoded);
