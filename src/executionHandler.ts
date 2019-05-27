import {
  IntegrationExecutionContext,
  IntegrationExecutionResult,
} from "@jupiterone/jupiter-managed-integration-sdk";

import { createAccountRelationships, createAgentEntities } from "./converters";
import initializeContext from "./initializeContext";
import ThreatStackClient from "./ThreatStackClient";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_TYPE,
  ThreatStackAccountEntity,
  ThreatStackAgentEntity,
} from "./types";

export default async function executionHandler(
  context: IntegrationExecutionContext,
): Promise<IntegrationExecutionResult> {
  const { graph, persister, provider } = initializeContext(context);

  const [
    oldAccountEntities,
    oldAgentEntities,
    oldAccountAgentRelationships,
  ] = await Promise.all([
    graph.findAllEntitiesByType<ThreatStackAccountEntity>(ACCOUNT_ENTITY_TYPE),
    graph.findEntitiesByType<ThreatStackAgentEntity>(AGENT_ENTITY_TYPE),
    graph.findRelationshipsByType(ACCOUNT_AGENT_RELATIONSHIP_TYPE),
  ]);

  const [newAgentEntities] = await Promise.all([
    fetchAgentEntitiesFromProvider(provider),
  ]);

  const accountEntity = provider.getAccountDetails();

  const newAccountAgentRelationships = createAccountRelationships(
    accountEntity,
    newAgentEntities,
    ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  );

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
      ],
    ]),
  };
}

async function fetchAgentEntitiesFromProvider(
  provider: ThreatStackClient,
): Promise<ThreatStackAgentEntity[]> {
  return [
    ...createAgentEntities(await provider.getServerAgents("online")),
    ...createAgentEntities(await provider.getServerAgents("offline")),
  ];
}
