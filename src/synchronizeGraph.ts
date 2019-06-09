import {
  IntegrationExecutionContext,
  IntegrationExecutionResult,
} from "@jupiterone/jupiter-managed-integration-sdk";

import {
  createAccountEntity,
  createAccountRelationships,
  createAgentEntities,
  createAgentFindingMappedRelationship,
} from "./converters";
import initializeContext from "./initializeContext";
import {
  createAgentCache,
  createVulnerabilityCache,
} from "./threatstack/cache";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_TYPE,
  AGENT_FINDING_RELATIONSHIP_TYPE,
  ThreatStackAccountEntity,
  ThreatStackAgentEntity,
} from "./types";
import getCVE from "./util/getCVE";

export default async function synchronizeGraph(
  context: IntegrationExecutionContext,
): Promise<IntegrationExecutionResult> {
  const { graph, persister } = initializeContext(context);

  const onlineAgentsCache = createAgentCache(
    context.clients.getCache(),
    "online",
  );

  const offlineAgentsCache = createAgentCache(
    context.clients.getCache(),
    "offline",
  );

  // TODO abort if collecting any data failed

  const [onlineAgentIds, offlineAgentIds] = await Promise.all([
    onlineAgentsCache.getIds(),
    offlineAgentsCache.getIds(),
  ]);

  const onlineAgents = onlineAgentIds
    ? (await onlineAgentsCache.getEntries(onlineAgentIds)).map(e => e.data)
    : [];
  const offlineAgents = offlineAgentIds
    ? (await offlineAgentsCache.getEntries(offlineAgentIds)).map(e => e.data)
    : [];

  const newAgentEntities = [
    ...createAgentEntities(onlineAgents),
    ...createAgentEntities(offlineAgents),
  ];

  const accountEntity = createAccountEntity(context.instance.config);

  const newAccountAgentRelationships = createAccountRelationships(
    accountEntity,
    newAgentEntities,
    ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  );

  const agentsById: { [id: string]: ThreatStackAgentEntity } = {};
  for (const agent of newAgentEntities || []) {
    agentsById[agent.id] = agent;
  }

  const vulnerabilitiesCache = createVulnerabilityCache(
    context.clients.getCache(),
  );

  const vunerabilityIds = await vulnerabilitiesCache.getIds();
  const vulnerabilities = vunerabilityIds
    ? (await vulnerabilitiesCache.getEntries(vunerabilityIds)).map(e => e.data)
    : [];

  const newVulnerabilityRelationships = [];

  for (const vulnData of vulnerabilities) {
    const { vulnerability: vuln, vulnerableServers } = vulnData;

    const cve = getCVE(vuln.cveNumber, {
      package: vuln.reportedPackage,
      severity: vuln.severity,
      vector: vuln.vectorType,
      findings: vuln.systemPackage,
    });

    cve.targets = [];

    for (const server of vulnerableServers) {
      const agent = agentsById[server.agentId];
      if (agent) {
        if (agent.instanceId) {
          cve.targets.push(agent.instanceId);
        } else {
          cve.targets.push(agent.hostname);
        }
        newVulnerabilityRelationships.push(
          createAgentFindingMappedRelationship(
            agent,
            cve,
            vuln.systemPackage,
            vuln.isSuppressed,
          ),
        );
      }
    }
  }

  const [
    oldAccountEntities,
    oldAgentEntities,
    oldAccountAgentRelationships,
    oldVulnerabilityRelationships,
  ] = await Promise.all([
    graph.findAllEntitiesByType<ThreatStackAccountEntity>(ACCOUNT_ENTITY_TYPE),
    graph.findEntitiesByType<ThreatStackAgentEntity>(AGENT_ENTITY_TYPE),
    graph.findRelationshipsByType(ACCOUNT_AGENT_RELATIONSHIP_TYPE),
    graph.findRelationshipsByType(AGENT_FINDING_RELATIONSHIP_TYPE),
  ]);

  return {
    operations: await persister.publishPersisterOperations([
      [
        ...persister.processEntities(oldAccountEntities, [accountEntity]),
        ...persister.processEntities(oldAgentEntities, newAgentEntities),
      ],
      [
        ...persister.processRelationships(
          oldAccountAgentRelationships,
          newAccountAgentRelationships,
        ),
        ...persister.processRelationships(
          oldVulnerabilityRelationships,
          newVulnerabilityRelationships,
        ),
      ],
    ]),
  };
}
