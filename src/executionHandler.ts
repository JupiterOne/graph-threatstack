import {
  IntegrationExecutionContext,
  IntegrationExecutionResult,
} from "@jupiterone/jupiter-managed-integration-sdk";

import {
  createAccountRelationships,
  createAgentEntities,
  createAgentFindingMappedRelationship,
} from "./converters";
import initializeContext from "./initializeContext";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_TYPE,
  AGENT_FINDING_RELATIONSHIP_TYPE,
  ThreatStackAccountEntity,
  ThreatStackAgentEntity,
} from "./types";
import getCVE from "./util/getCVE";

export default async function executionHandler(
  context: IntegrationExecutionContext,
): Promise<IntegrationExecutionResult> {
  const { graph, persister, provider } = initializeContext(context);

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

  const [onlineAgents, offlineAgents, vulnerabilities] = await Promise.all([
    provider.getServerAgents("online"),
    provider.getServerAgents("offline"),
    provider.getVulnerabilities(),
  ]);

  const newAgentEntities = [
    ...createAgentEntities(onlineAgents),
    ...createAgentEntities(offlineAgents),
  ];

  const accountEntity = provider.getAccountDetails();

  const newAccountAgentRelationships = createAccountRelationships(
    accountEntity,
    newAgentEntities,
    ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  );

  const agentsById: { [id: string]: ThreatStackAgentEntity } = {};
  for (const agent of newAgentEntities) {
    agentsById[agent.id] = agent;
  }

  const newVulnerabilityRelationships = [];

  for (const vuln of vulnerabilities) {
    const cve = getCVE(vuln.cveNumber, {
      open: !vuln.isSuppressed,
      suppressed: vuln.isSuppressed,
      package: vuln.reportedPackage,
      severity: vuln.severity,
      vector: vuln.vectorType,
      finding: vuln.systemPackage,
    });
    cve.targets = [];
    const vulnerableServers = await provider.getVulnerableServers(
      vuln.cveNumber,
    );
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
