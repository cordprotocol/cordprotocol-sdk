#!/usr/bin/env node
import { Command } from 'commander';
import { generateKeyPair } from './crypto/keys.js';
import { issueCredential } from './issuer.js';
import { verifyCredential } from './verifier.js';

const program = new Command();

program
  .name('cord')
  .description('Cord Protocol CLI — post-quantum AI agent credential management')
  .version('0.1.0');

// ─── keygen ───────────────────────────────────────────────────────────────────

program
  .command('keygen')
  .description('Generate a new Ed25519 key pair for credential issuance')
  .action(async () => {
    const kp = await generateKeyPair();
    console.log('\nKey Pair Generated\n' + '═'.repeat(60));
    console.log(`Public Key:  ${kp.publicKeyBase64}`);
    console.log(`Private Key: ${kp.privateKeyBase64}`);
    console.log('\nWARNING: Store your private key securely. Never share it.\n');
  });

// ─── issue ────────────────────────────────────────────────────────────────────

program
  .command('issue')
  .description('Issue a signed agent credential')
  .requiredOption('--agent-id <id>', 'Unique identifier for the agent')
  .requiredOption('--issued-to <name>', 'Owner of this agent (person or organization)')
  .requiredOption(
    '--permissions <scopes>',
    'Comma-separated permission scopes, e.g. "read:data,write:orders,spend:500"',
  )
  .option('--expires <duration>', 'Expiry: "30m", "24h", "7d", "2w", or ISO timestamp', '24h')
  .option('--private-key <base64>', 'Issuer private key (base64). Generates a new pair if omitted.')
  .option('--attestation-data <string>', 'String to hash for agent attestation (e.g. config JSON)')
  .action(async (opts) => {
    try {
      let privateKeyB64: string;

      if (opts.privateKey) {
        privateKeyB64 = opts.privateKey;
      } else {
        console.log('No --private-key provided — generating new key pair...\n');
        const kp = await generateKeyPair();
        privateKeyB64 = kp.privateKeyBase64;
        console.log(`Issuer Public Key:  ${kp.publicKeyBase64}`);
        console.log(`Issuer Private Key: ${kp.privateKeyBase64}`);
        console.log('\nSave these keys to issue credentials from this authority later.\n');
      }

      const permissions = opts.permissions
        .split(',')
        .map((s: string) => s.trim())
        .filter(Boolean);

      const credential = await issueCredential(
        {
          agentId: opts.agentId,
          issuedTo: opts.issuedTo,
          permissions,
          expiresIn: opts.expires,
          attestationData: opts.attestationData,
        },
        privateKeyB64,
      );

      const encoded = Buffer.from(JSON.stringify(credential)).toString('base64');

      console.log('Credential Issued\n' + '═'.repeat(60));
      console.log('\nBase64 (pass this to `cord verify --credential`):');
      console.log(encoded);
      console.log('\nJSON:');
      console.log(JSON.stringify(credential, null, 2));
      console.log('');
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

// ─── verify ───────────────────────────────────────────────────────────────────

program
  .command('verify')
  .description('Verify an agent credential')
  .requiredOption('--credential <base64>', 'Base64-encoded credential to verify')
  .action(async (opts) => {
    try {
      const result = await verifyCredential(opts.credential);

      console.log('\nVerification Result\n' + '═'.repeat(60));

      if (result.valid) {
        const c = result.credential!;
        console.log('Status:        VALID');
        console.log(`Credential ID: ${c.id}`);
        console.log(`Agent ID:      ${c.agentId}`);
        console.log(`Issued To:     ${c.issuedTo}`);
        console.log(`Issued At:     ${new Date(c.issuedAt).toLocaleString()}`);
        console.log(`Expires At:    ${new Date(c.expiresAt).toLocaleString()}`);
        console.log(`Permissions:   ${c.permissions.join(', ')}`);
      } else {
        console.log('Status: INVALID');
        result.errors.forEach((e) => console.log(`  • ${e}`));
      }

      console.log('');
      process.exit(result.valid ? 0 : 1);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program.parse();
