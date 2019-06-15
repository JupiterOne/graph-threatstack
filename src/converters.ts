import {
  EntityFromIntegration,
  RelationshipDirection,
  RelationshipFromIntegration,
} from "@jupiterone/jupiter-managed-integration-sdk";

import { ThreatStackAgent } from "./threatstack/types";
import {
  ACCOUNT_ENTITY_CLASS,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_CLASS,
  AGENT_ENTITY_TYPE,
  AGENT_FINDING_RELATIONSHIP_TYPE,
  PROVIDER_NAME,
  ThreatStackAccountEntity,
  ThreatStackAgentEntity,
  ThreatStackAgentFindingRelationship,
  ThreatStackIntegrationConfig,
} from "./types";
import { CVE } from "./util/getCVE";
import getTime from "./util/getTime";
import { normalizeHostname } from "./util/normalizeHostname";

export function createAccountEntity(
  data: ThreatStackIntegrationConfig,
): ThreatStackAccountEntity {
  return {
    _key: `${PROVIDER_NAME}:account:${data.orgId}`,
    _type: ACCOUNT_ENTITY_TYPE,
    _class: ACCOUNT_ENTITY_CLASS,
    accountId: data.orgId,
    name: data.orgName,
    displayName: `Threat Stack - ${data.orgName}`,
  };
}

export function createAgentEntities(
  data: ThreatStackAgent[],
): ThreatStackAgentEntity[] {
  const agents = [];

  for (const item of data) {
    const ipAddresses = [];
    const publicIpAddress = item.ipAddresses
      ? item.ipAddresses.public
      : undefined;
    const privateIpAddress = item.ipAddresses
      ? item.ipAddresses.private
      : undefined;
    const macAddress = item.ipAddresses
      ? item.ipAddresses.link_local
      : undefined;
    if (item.ipAddresses) {
      ipAddresses.push(...item.ipAddresses.public, ...item.ipAddresses.private);
    }

    agents.push({
      _key: `${PROVIDER_NAME}:agent:${item.id}`,
      _class: AGENT_ENTITY_CLASS,
      _type: AGENT_ENTITY_TYPE,
      displayName: item.name || (item.hostname as string),
      id: item.id,
      instanceId: item.instanceId,
      status: item.status,
      active: item.status.toLowerCase() === "online",
      version: item.version,
      name: item.name,
      description: item.description,
      hostname: normalizeHostname(item.hostname),
      ipAddresses,
      publicIpAddress,
      privateIpAddress,
      macAddress,
      agentType: item.agentType,
      kernel: item.kernel,
      osVersion: item.osVersion,
      createdAt: getTime(item.createdAt),
      lastReportedAt: getTime(item.lastReportedAt),
      createdOn: getTime(item.createdAt),
      function: ["FIM", "activity-monitor", "vulnerability-scan"],
    });
  }

  return agents;
}

export function createAccountRelationships(
  account: ThreatStackAccountEntity,
  entities: EntityFromIntegration[],
  type: string,
) {
  const relationships = [];
  for (const entity of entities) {
    relationships.push(createAccountRelationship(account, entity, type));
  }
  return relationships;
}

export function createAccountRelationship(
  account: ThreatStackAccountEntity,
  entity: EntityFromIntegration,
  type: string,
): RelationshipFromIntegration {
  return {
    _class: "HAS",
    _fromEntityKey: account._key,
    _key: `${account._key}|has|${entity._key}`,
    _toEntityKey: entity._key,
    _type: type,
    displayName: "HAS",
  };
}

export function createAgentFindingMappedRelationship(
  agent: ThreatStackAgentEntity,
  cve: CVE,
  finding?: string,
  suppressed?: boolean,
): ThreatStackAgentFindingRelationship {
  return {
    _key: `${agent._key}|identified|${cve._key}`,
    _type: AGENT_FINDING_RELATIONSHIP_TYPE,
    _class: "IDENTIFIED",
    displayName: "IDENTIFIED",
    finding,
    suppressed,
    _mapping: {
      sourceEntityKey: agent._key,
      relationshipDirection: RelationshipDirection.FORWARD,
      targetFilterKeys: [["_type", "_key"]],
      targetEntity: cve as any,
    },
  };
}
