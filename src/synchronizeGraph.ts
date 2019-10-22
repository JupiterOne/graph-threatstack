import {
  IntegrationCacheEntry,
  IntegrationError,
  IntegrationExecutionContext,
  IntegrationExecutionResult,
  PersisterOperationsResult,
  summarizePersisterOperationsResults,
} from "@jupiterone/jupiter-managed-integration-sdk";
import { IterableCache } from "@jupiterone/jupiter-managed-integration-sdk/integration/cache/types";
import {
  createAccountEntity,
  createAccountRelationships,
  createAgentEntities,
  createAgentFindingMappedRelationship,
} from "./converters";
import initializeContext from "./initializeContext";
import { ThreatStackAgent } from "./threatstack/types";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_TYPE,
  AGENT_FINDING_RELATIONSHIP_TYPE,
  ResourceCacheState,
  ThreatStackAccountEntity,
  ThreatStackAgentEntity,
  ThreatStackAgentFindingRelationship,
  ThreatStackExecutionContext,
} from "./types";
import getCVE from "./util/getCVE";

export default async function synchronizeGraph(
  executionContext: IntegrationExecutionContext,
): Promise<IntegrationExecutionResult> {
  const context = initializeContext(executionContext);
  const { cache } = context;

  const onlineAgentsCache = cache.iterableCache<
    IntegrationCacheEntry,
    ResourceCacheState
  >("onlineAgents");
  const offlineAgentsCache = cache.iterableCache<
    IntegrationCacheEntry,
    ResourceCacheState
  >("offlineAgents");
  const vulnerabilitiesCache = cache.iterableCache<
    IntegrationCacheEntry,
    ResourceCacheState
  >("vulnerabilities");

  const [
    onlineAgentsState,
    offlineAgentsState,
    vulnerabilitiesState,
  ] = await Promise.all([
    onlineAgentsCache.getState(),
    offlineAgentsCache.getState(),
    vulnerabilitiesCache.getState(),
  ]);

  if (
    !(
      onlineAgentsState &&
      onlineAgentsState.resourceFetchCompleted &&
      (offlineAgentsState && offlineAgentsState.resourceFetchCompleted) &&
      (vulnerabilitiesState && vulnerabilitiesState.resourceFetchCompleted)
    )
  ) {
    throw new IntegrationError({
      message: "Failed to fetch data from provider",
      expose: true,
    });
  }

  const results: PersisterOperationsResult[] = [];
  const accountEntity = createAccountEntity(context.instance.config);

  results.push(await synchronizeAccount(context, accountEntity));

  const onlineAgents: ThreatStackAgent[] = [];
  await onlineAgentsCache.forEach(e => {
    onlineAgents.push(e.data);
  });

  const offlineAgents: ThreatStackAgent[] = [];
  await offlineAgentsCache.forEach(e => {
    offlineAgents.push(e.data);
  });

  const newAgentEntities = [
    ...createAgentEntities(onlineAgents),
    ...createAgentEntities(offlineAgents),
  ];

  results.push(await synchronizeAgentEntities(context, newAgentEntities));
  results.push(
    await synchronizeAccountAgentRelationships(
      context,
      accountEntity,
      newAgentEntities,
    ),
  );

  results.push(
    await synchronizeVulnerabilities(
      context,
      newAgentEntities,
      vulnerabilitiesCache,
    ),
  );

  return {
    operations: summarizePersisterOperationsResults(...results),
  };
}

async function synchronizeAccount(
  context: ThreatStackExecutionContext,
  accountEntity: ThreatStackAccountEntity,
): Promise<PersisterOperationsResult> {
  const { persister, graph } = context;
  const oldAccountEntities = await graph.findAllEntitiesByType<
    ThreatStackAccountEntity
  >(ACCOUNT_ENTITY_TYPE);
  return await persister.publishEntityOperations(
    await persister.processEntities(oldAccountEntities, [accountEntity]),
  );
}

async function synchronizeAgentEntities(
  context: ThreatStackExecutionContext,
  agentEntities: ThreatStackAgentEntity[],
): Promise<PersisterOperationsResult> {
  const { persister, graph } = context;
  const oldAgentEntities = await graph.findEntitiesByType<
    ThreatStackAgentEntity
  >(AGENT_ENTITY_TYPE);
  return await persister.publishEntityOperations(
    await persister.processEntities(oldAgentEntities, agentEntities),
  );
}

async function synchronizeAccountAgentRelationships(
  context: ThreatStackExecutionContext,
  accountEntity: ThreatStackAccountEntity,
  agentEntities: ThreatStackAgentEntity[],
): Promise<PersisterOperationsResult> {
  const { persister, graph } = context;

  return await persister.publishRelationshipOperations(
    persister.processRelationships(
      await graph.findRelationshipsByType(ACCOUNT_AGENT_RELATIONSHIP_TYPE),
      createAccountRelationships(
        accountEntity,
        agentEntities,
        ACCOUNT_AGENT_RELATIONSHIP_TYPE,
      ),
    ),
  );
}

async function synchronizeVulnerabilities(
  context: ThreatStackExecutionContext,
  agents: ThreatStackAgentEntity[],
  vulnerabilityCache: IterableCache<IntegrationCacheEntry, ResourceCacheState>,
): Promise<PersisterOperationsResult> {
  const { persister, graph } = context;

  const agentsById: { [id: string]: ThreatStackAgentEntity } = {};
  for (const agent of agents || []) {
    agentsById[agent.id] = agent;
  }

  const newVulnerabilityRelationships: ThreatStackAgentFindingRelationship[] = [];

  // Build relationships by iterating, dropping raw data after it is processed.
  await vulnerabilityCache.forEach(e => {
    const { vulnerability: vuln, vulnerableServers } = e.data;

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
  });

  const oldVulnerabilityRelationships = await graph.findRelationshipsByType(
    AGENT_FINDING_RELATIONSHIP_TYPE,
  );

  return persister.publishRelationshipOperations(
    await persister.processRelationships(
      oldVulnerabilityRelationships,
      newVulnerabilityRelationships,
    ),
  );
}
