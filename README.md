# @cordprotocol/sdk

Post-quantum cryptographic identity for AI agents.

[![npm version](https://img.shields.io/npm/v/@cordprotocol/sdk)](https://www.npmjs.com/package/@cordprotocol/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What is Cord Protocol?

Cord Protocol is a cryptographic identity layer for AI agents. As autonomous agents proliferate across enterprise software — reading data, placing orders, sending messages, spending money — the question of *who authorized this agent, and what is it allowed to do?* becomes critical. Cord solves this by issuing signed, verifiable credentials to agents at deploy time. Any service the agent talks to can verify the credential in milliseconds with no server call: the issuer's public key is embedded directly in the credential, and the Ed25519 signature covers every field including permissions and expiry. Tampering with any field breaks the signature instantly.

---

## Installation

```bash
npm install @cordprotocol/sdk
```

**Requirements:** Node.js ≥ 18.0.0

---

## Quick Start

Issue and verify an agent credential in under 10 lines:

```typescript
import { generateKeyPair, issueCredential, verifyCredential } from '@cordprotocol/sdk';

// One-time setup: generate an issuer key pair and store securely
const keyPair = await generateKeyPair();

// Issue a credential for an agent
const credential = await issueCredential(
  {
    agentId: 'order-bot-v1',
    issuedTo: 'Acme Corp',
    permissions: ['read:data', 'write:orders', 'spend:500'],
    expiresIn: '24h',
  },
  keyPair.privateKeyBase64,
);

// Verify the credential (no server call needed)
const result = await verifyCredential(credential);
console.log(result.valid); // true
console.log(result.credential?.permissions); // ['read:data', 'write:orders', 'spend:500']
```

---

## CLI

```bash
# Generate a key pair
cord keygen

# Issue a credential (generates a new key pair if --private-key is omitted)
cord issue \
  --agent-id "my-agent" \
  --issued-to "Acme Corp" \
  --permissions "read:data,write:orders,spend:500" \
  --expires "24h"

# Verify a credential
cord verify --credential <base64>
```

---

## API Reference

### `generateKeyPair(): Promise<KeyPair>`

Generates a new Ed25519 key pair using a cryptographically secure RNG.

```typescript
const { publicKey, privateKey, publicKeyBase64, privateKeyBase64 } = await generateKeyPair();
```

**Returns:** `KeyPair`

| Field | Type | Description |
|---|---|---|
| `publicKey` | `Uint8Array` | Raw 32-byte public key |
| `privateKey` | `Uint8Array` | Raw 32-byte private key — keep secret |
| `publicKeyBase64` | `string` | Base64-encoded public key |
| `privateKeyBase64` | `string` | Base64-encoded private key |

---

### `issueCredential(params, privateKey): Promise<AgentCredential>`

Issues a signed credential for an agent.

```typescript
const credential = await issueCredential(
  {
    agentId: 'my-agent',
    issuedTo: 'Acme Corp',
    permissions: ['read:data', 'write:orders'],
    expiresIn: '24h',                        // optional, default "24h"
    attestationData: JSON.stringify(config), // optional
  },
  privateKeyBase64, // string or Uint8Array
);
```

**Parameters:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agentId` | `string` | Yes | Identifier for the agent |
| `issuedTo` | `string` | Yes | Owner (person or organization) |
| `permissions` | `string[]` | Yes | Permission scopes (e.g. `["read:data", "spend:500"]`) |
| `expiresIn` | `string` | No | Duration (`"30m"`, `"24h"`, `"7d"`, `"2w"`) or ISO 8601 timestamp. Defaults to `"24h"` |
| `attestationData` | `string` | No | Arbitrary string to hash for code attestation |

---

### `verifyCredential(credential): Promise<VerificationResult>`

Verifies a credential's schema, expiry, and cryptographic signature. No network call required.

Accepts either a parsed `AgentCredential` object or a base64-encoded JSON string.

```typescript
const result = await verifyCredential(credential);
// or
const result = await verifyCredential(base64String);

if (!result.valid) {
  console.error(result.errors); // ['Credential expired at ...']
}
```

**Returns:** `VerificationResult`

| Field | Type | Description |
|---|---|---|
| `valid` | `boolean` | `true` only when schema, expiry, and signature all pass |
| `errors` | `string[]` | Human-readable error messages (empty when valid) |
| `credential` | `AgentCredential \| undefined` | Parsed credential when structurally valid |

---

### `isExpired(credential): boolean`

Returns `true` if the credential's `expiresAt` is in the past.

```typescript
if (isExpired(credential)) {
  // reject the agent
}
```

---

### `hasPermission(credential, scope): boolean`

Returns `true` if the credential contains the given permission scope (exact string match).

```typescript
if (!hasPermission(credential, 'write:orders')) {
  throw new Error('Agent not authorized to write orders');
}
```

---

### `SCOPES` — Standard Permission Constants

```typescript
import { SCOPES } from '@cordprotocol/sdk';

SCOPES.READ_DATA          // 'read:data'
SCOPES.READ_MEMORY        // 'read:memory'
SCOPES.READ_CONTEXT       // 'read:context'
SCOPES.WRITE_DATA         // 'write:data'
SCOPES.WRITE_ORDERS       // 'write:orders'
SCOPES.WRITE_MESSAGES     // 'write:messages'
SCOPES.EXECUTE_CODE       // 'execute:code'
SCOPES.EXECUTE_TOOLS      // 'execute:tools'
SCOPES.COMMUNICATE_EMAIL  // 'communicate:email'
SCOPES.COMMUNICATE_API    // 'communicate:api'
SCOPES.COMMUNICATE_WEBHOOK // 'communicate:webhook'
```

Custom scopes are supported: any string matching `<word>:<word_or_number>` is valid
(e.g. `"spend:500"`, `"invoice:create"`, `"database:customers"`).

---

### `validateScopes(scopes): boolean`

Returns `true` if every scope in the array is well-formed.

---

### `parseSpendLimit(scope): number | null`

Parses a spend scope and returns the numeric limit, or `null` if not a spend scope.

```typescript
parseSpendLimit('spend:500')   // 500
parseSpendLimit('spend:99.99') // 99.99
parseSpendLimit('read:data')   // null
```

---

### `AgentCredential` — Credential Schema

```typescript
interface AgentCredential {
  id: string;              // UUID v4
  agentId: string;         // agent identifier
  issuedTo: string;        // owner name
  issuedAt: string;        // ISO 8601
  expiresAt: string;       // ISO 8601
  permissions: string[];   // scope strings
  attestationHash: string; // base64 SHA-256 of attestationData
  issuerPublicKey: string; // base64 Ed25519 public key
  signature: string;       // base64 Ed25519 signature over all other fields
}
```

---

## Why Post-Quantum?

Current AI agent deployments can be secured today with Ed25519 — a fast, battle-tested elliptic curve algorithm trusted by TLS, SSH, and cryptocurrency systems worldwide. However, sufficiently powerful quantum computers running Shor's algorithm will be able to break elliptic curve cryptography. NIST finalized post-quantum standards in 2024 (FIPS 203/204/205), with **CRYSTALS-Dilithium (ML-DSA)** as the primary digital signature algorithm.

The Cord SDK is designed for a seamless migration path:

- The `CryptoBackend` interface isolates all signing and verification behind a single swappable abstraction
- `generateKeyPair()` and `derivePublicKey()` in `crypto/keys.ts` are the only algorithm-specific code
- Credentials encode keys and signatures as base64 strings — byte size differences between Ed25519 and Dilithium are absorbed transparently
- When `@noble/post-quantum` (or equivalent) reaches production maturity, **only two files change**: `crypto/keys.ts` and `crypto/signatures.ts`. No consumer code changes.

Existing Ed25519 credentials will not verify against a Dilithium backend, so plan a credential rotation window when you migrate.

---

## Transport

Credentials are self-contained JSON objects. For transport over HTTP, encode as base64:

```typescript
// Encode
const token = Buffer.from(JSON.stringify(credential)).toString('base64');

// Decode (or just pass the base64 string directly to verifyCredential)
const result = await verifyCredential(token);
```

Common transport patterns:
- **HTTP header**: `X-Agent-Credential: <base64>`
- **Bearer token**: `Authorization: Bearer <base64>`
- **Message queue**: include in message metadata
- **Database**: store as a `TEXT` column alongside agent records

---

## Security Considerations

- **Store private keys securely.** Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.). Never log or transmit private keys.
- **Short expiry windows** limit blast radius if a credential is stolen. Use `"1h"` or `"8h"` rather than `"30d"`.
- **Attestation hashes** bind a credential to a specific version of agent code. Hash the deployed bundle or config file at issue time. A credential issued against `v1.0.0` will not validate that the agent is running `v2.0.0` — that enforcement is up to your runtime.
- **No revocation in Phase 1.** Short credential lifetimes are the primary defense. A revocation registry is planned for a future release.

---

## License

MIT © Cord Protocol

---

[cordprotocol.dev](https://cordprotocol.dev)
