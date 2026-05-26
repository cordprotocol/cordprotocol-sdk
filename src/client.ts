import type { AgentCredential, IssueCredentialParams, VerificationResult } from './credential.js';
import { issueCredential as coreIssueCredential } from './issuer.js';
import { verifyCredential as coreVerifyCredential } from './verifier.js';
import {
  registerAgent,
  lookupAgent as registryLookupAgent,
  checkRevocationStatus,
  revokeCredential as registryRevokeCredential,
} from './registry.js';
import type { AgentRegistration } from './registry.js';

export type { AgentRegistration };

const DEFAULT_API_URL = 'https://api.cordprotocol.dev';

export interface CordProtocolConfig {
  registry?: boolean;
  apiKey?: string;
  apiUrl?: string;
}

export class CordProtocol {
  private readonly registry: boolean;
  private readonly apiKey: string | undefined;
  private readonly apiUrl: string;

  constructor(config: CordProtocolConfig = {}) {
    this.registry = config.registry ?? false;
    this.apiKey = config.apiKey;
    this.apiUrl = config.apiUrl ?? DEFAULT_API_URL;
  }

  async issueCredential(
    params: IssueCredentialParams,
    privateKey: string,
  ): Promise<AgentCredential> {
    const credential = await coreIssueCredential(params, privateKey);

    if (this.registry) {
      try {
        await registerAgent(
          credential.agentId,
          credential.issuerPublicKey,
          credential.issuedTo,
          undefined,
          this.apiUrl,
        );
      } catch {
        // Fail silently — registry failure never blocks credential issuance
      }
    }

    return credential;
  }

  async verifyCredential(credential: AgentCredential | string): Promise<VerificationResult> {
    const result = await coreVerifyCredential(credential);

    if (result.valid && result.credential && this.apiKey) {
      try {
        const status = await checkRevocationStatus(result.credential.id, this.apiUrl);
        if (status.revoked) {
          return {
            valid: false,
            errors: [`Credential has been revoked${status.reason ? `: ${status.reason}` : ''}`],
            credential: result.credential,
          };
        }
      } catch {
        // Fail silently — local verification result stands when revocation check errors
      }
    }

    return result;
  }

  async revokeCredential(
    credentialId: string,
    agentId: string,
    reason?: string,
  ): Promise<void> {
    if (!this.apiKey) {
      throw new Error('apiKey is required to revoke credentials');
    }
    await registryRevokeCredential(credentialId, agentId, this.apiKey, reason, this.apiUrl);
  }

  async lookupAgent(agentId: string): Promise<AgentRegistration | null> {
    return registryLookupAgent(agentId, this.apiUrl);
  }
}
