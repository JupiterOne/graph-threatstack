import {
  EntityFromIntegration,
  GraphClient,
  IntegrationExecutionContext,
  MappedRelationshipFromIntegration,
  PersisterClient,
} from "@jupiterone/jupiter-managed-integration-sdk";

import ThreatStackClient from "./ThreatStackClient";

export const PROVIDER_NAME = "threatstack";

export const ACCOUNT_ENTITY_TYPE = PROVIDER_NAME + "_account";
export const ACCOUNT_ENTITY_CLASS = "Account";

export const AGENT_ENTITY_TYPE = "threatstack_agent";
export const AGENT_ENTITY_CLASS = "HostAgent";

export const ACCOUNT_AGENT_RELATIONSHIP_TYPE =
  ACCOUNT_ENTITY_TYPE + "_has_agent";

export const AGENT_FINDING_RELATIONSHIP_TYPE =
  PROVIDER_NAME + "_agent_identified_vulnerability";

export interface ThreatStackIntegrationConfig {
  apiKey: string;
  orgId: string;
  orgName: string;
  userId: string;
}

export interface ThreatStackExecutionContext
  extends IntegrationExecutionContext {
  graph: GraphClient;
  persister: PersisterClient;
  provider: ThreatStackClient;
}

export interface ThreatStackAccountEntity extends EntityFromIntegration {
  accountId: string;
  name: string;
}

export interface ThreatStackAgentEntity extends EntityFromIntegration {
  active: boolean;
  id: string;
  instanceId?: string | null;
  status: string;
  createdAt: number | undefined;
  lastReportedAt: number | undefined;
  version: string;
  name?: string | null;
  description?: string | null;
  hostname: string;
  ipAddresses: string[] | undefined;
  publicIpAddress: string | string[] | undefined;
  privateIpAddress: string | string[] | undefined;
  macAddress: string | string[] | undefined;
  agentType: string;
  kernel?: string | null;
  osVersion?: string | null;
  createdOn?: number;
  updatedOn?: number;
  function?: string[];
}

export interface ThreatStackAgentFindingRelationship
  extends MappedRelationshipFromIntegration {
  finding?: string;
  suppressed?: boolean;
}
