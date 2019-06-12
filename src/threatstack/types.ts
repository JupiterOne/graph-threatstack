export interface ThreatStackAgentIpAddresses {
  private: string | string[];
  link_local: string | string[];
  public: string | string[];
}

export interface ThreatStackAgentTags {
  source?: string | null;
  key?: string | null;
  value?: string | null;
}

export interface ThreatStackAgent {
  id: string;
  instanceId?: string | null;
  status: string;
  createdAt: string;
  lastReportedAt: string;
  version: string;
  name?: string | null;
  description?: string | null;
  hostname: string;
  ipAddresses?: ThreatStackAgentIpAddresses | null;
  tags?: ThreatStackAgentTags[] | null;
  agentType: string;
  kernel?: string | null;
  osVersion?: string | null;
}

export type ThreatStackAgentStatus = "online" | "offline";

export interface ThreatStackVulnerability {
  cveNumber: string;
  reportedPackage: string;
  systemPackage: string;
  vectorType: string;
  severity: string;
  isSuppressed: boolean;
}

export interface ThreatStackVulnerableServer {
  agentId: string;
  hostname?: string | null;
}
