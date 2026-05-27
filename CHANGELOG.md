# Changelog

All notable changes to @cordprotocol/sdk will be 
documented in this file.

## [0.4.0] - 2026-05-27

### Added
- W3C DID (Decentralized Identifier) support
- Verifiable Credential issuance and verification
- did:web and did:key resolution
- agentIdToDID() and didToAgentId() helpers
- Full W3C VC format compatibility
- Backwards compatible — all existing APIs unchanged

## [0.2.0] - 2026-05-22

### Added
- CordProtocol client class with registry integration
- Registry auto-posting on issueCredential()
- Revocation checking on verifyCredential()
- Standalone registry and revocation functions
- Connected to api.cordprotocol.dev hosted API

## [0.1.0] - 2026-05-18

### Added
- Initial release
- Agent credential issuance with Ed25519 signatures
- Credential verification (signature, expiry, schema)
- Permission scope system with SCOPES constants
- Attestation hash support
- CLI tool (cord keygen, cord issue, cord verify)
- 38 passing tests
- TypeScript with full type exports
