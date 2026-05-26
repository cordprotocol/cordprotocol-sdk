const DEFAULT_API_URL = 'https://api.cordprotocol.dev';

export interface AgentRegistration {
  id: string;
  agentId: string;
  publicKey: string;
  issuedTo: string;
  domain?: string;
  registeredAt: string;
  credentialCount: number;
  active: boolean;
}

export async function registerAgent(
  agentId: string,
  publicKey: string,
  issuedTo: string,
  domain?: string,
  apiUrl?: string,
): Promise<AgentRegistration> {
  const url = `${apiUrl ?? DEFAULT_API_URL}/v1/registry/agents`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId, publicKey, issuedTo, domain }),
  });
  if (!response.ok) {
    throw new Error(`Registry error: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<AgentRegistration>;
}

export async function lookupAgent(
  agentId: string,
  apiUrl?: string,
): Promise<AgentRegistration | null> {
  const url = `${apiUrl ?? DEFAULT_API_URL}/v1/registry/agents/${encodeURIComponent(agentId)}`;
  const response = await fetch(url);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Registry lookup error: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<AgentRegistration>;
}

export async function checkRevocationStatus(
  credentialId: string,
  apiUrl?: string,
): Promise<{ revoked: boolean; revokedAt?: string; reason?: string }> {
  const url = `${apiUrl ?? DEFAULT_API_URL}/v1/credentials/${encodeURIComponent(credentialId)}/status`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Revocation check error: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<{ revoked: boolean; revokedAt?: string; reason?: string }>;
}

export async function revokeCredential(
  credentialId: string,
  agentId: string,
  apiKey: string,
  reason?: string,
  apiUrl?: string,
): Promise<void> {
  const url = `${apiUrl ?? DEFAULT_API_URL}/v1/credentials/revoke`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ credentialId, agentId, reason }),
  });
  if (!response.ok) {
    throw new Error(`Revocation error: ${response.status} ${response.statusText}`);
  }
}
