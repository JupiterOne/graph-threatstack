import { IntegrationExecutionContext } from "@jupiterone/jupiter-managed-integration-sdk";

import {
  accountEntity,
  agents,
  cves,
  vulnerableServers,
} from "./converters.test";
import executionHandler from "./executionHandler";
import initializeContext from "./initializeContext";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_TYPE,
} from "./types";

jest.mock("./initializeContext");

test("executionHandler", async () => {
  const executionContext: any = {
    graph: {
      findAllEntitiesByType: jest.fn().mockResolvedValue([]),
      findEntitiesByType: jest.fn().mockResolvedValue([]),
      findAllRelationshipsByType: jest.fn().mockResolvedValue([]),
      findRelationshipsByType: jest.fn().mockResolvedValue([]),
    },
    persister: {
      processEntities: jest.fn().mockReturnValue([]),
      processRelationships: jest.fn().mockReturnValue([]),
      publishPersisterOperations: jest.fn().mockResolvedValue({}),
    },
    provider: {
      getAccountDetails: jest.fn().mockResolvedValue(accountEntity),
      getServerAgents: jest.fn().mockResolvedValue(agents),
      getVulnerabilities: jest.fn().mockResolvedValue(cves),
      getVulnerableServers: jest.fn().mockResolvedValue(vulnerableServers),
    },
  };

  (initializeContext as jest.Mock).mockReturnValue(executionContext);

  const invocationContext = {} as IntegrationExecutionContext;
  await executionHandler(invocationContext);

  expect(initializeContext).toHaveBeenCalledWith(invocationContext);

  expect(executionContext.graph.findAllEntitiesByType).toHaveBeenCalledWith(
    ACCOUNT_ENTITY_TYPE,
  );
  expect(executionContext.graph.findEntitiesByType).toHaveBeenCalledWith(
    AGENT_ENTITY_TYPE,
  );
  expect(executionContext.graph.findRelationshipsByType).toHaveBeenCalledWith(
    ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  );

  expect(executionContext.provider.getAccountDetails).toHaveBeenCalledTimes(1);
  expect(executionContext.provider.getServerAgents).toHaveBeenCalledTimes(2);

  // account, agents
  expect(executionContext.persister.processEntities).toHaveBeenCalledTimes(2);

  // account -HAS-> agents; agent -IDENTIFIED-> cve
  expect(executionContext.persister.processRelationships).toHaveBeenCalledTimes(
    2,
  );
  expect(
    executionContext.persister.publishPersisterOperations,
  ).toHaveBeenCalledTimes(1);
});

test("should handle undefined vulnerable servers", async () => {
  const executionContext: any = {
    graph: {
      findAllEntitiesByType: jest.fn().mockResolvedValue([]),
      findEntitiesByType: jest.fn().mockResolvedValue([]),
      findAllRelationshipsByType: jest.fn().mockResolvedValue([]),
      findRelationshipsByType: jest.fn().mockResolvedValue([]),
    },
    persister: {
      processEntities: jest.fn().mockReturnValue([]),
      processRelationships: jest.fn().mockReturnValue([]),
      publishPersisterOperations: jest.fn().mockResolvedValue({}),
    },
    provider: {
      getAccountDetails: jest.fn().mockResolvedValue(accountEntity),
      getServerAgents: jest.fn().mockResolvedValue(undefined),
      getVulnerabilities: jest.fn().mockResolvedValue(undefined),
      getVulnerableServers: jest.fn().mockResolvedValue(vulnerableServers),
    },
  };

  (initializeContext as jest.Mock).mockReturnValue(executionContext);

  const invocationContext = {} as IntegrationExecutionContext;
  await executionHandler(invocationContext);

  expect(initializeContext).toHaveBeenCalledWith(invocationContext);

  expect(executionContext.graph.findAllEntitiesByType).toHaveBeenCalledWith(
    ACCOUNT_ENTITY_TYPE,
  );
  expect(executionContext.graph.findEntitiesByType).toHaveBeenCalledWith(
    AGENT_ENTITY_TYPE,
  );
  expect(executionContext.graph.findRelationshipsByType).toHaveBeenCalledWith(
    ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  );

  expect(executionContext.provider.getAccountDetails).toHaveBeenCalledTimes(1);
  expect(executionContext.provider.getServerAgents).toHaveBeenCalledTimes(2);

  // account
  expect(executionContext.persister.processEntities).toHaveBeenCalledTimes(1);

  expect(executionContext.persister.processRelationships).toHaveBeenCalledTimes(
    0,
  );
  expect(
    executionContext.persister.publishPersisterOperations,
  ).toHaveBeenCalledTimes(1);
});

test("executionHandler", async () => {
  const executionContext: any = {
    graph: {
      findAllEntitiesByType: jest.fn().mockResolvedValue([]),
      findEntitiesByType: jest.fn().mockResolvedValue([]),
      findAllRelationshipsByType: jest.fn().mockResolvedValue([]),
      findRelationshipsByType: jest.fn().mockResolvedValue([]),
    },
    persister: {
      processEntities: jest.fn().mockReturnValue([]),
      processRelationships: jest.fn().mockReturnValue([]),
      publishPersisterOperations: jest.fn().mockResolvedValue({}),
    },
    provider: {
      getAccountDetails: jest.fn().mockResolvedValue(accountEntity),
      getServerAgents: jest.fn().mockResolvedValue(agents),
      getVulnerabilities: jest.fn().mockResolvedValue(cves),
      getVulnerableServers: jest.fn().mockResolvedValue(undefined),
    },
  };

  (initializeContext as jest.Mock).mockReturnValue(executionContext);

  const invocationContext = {} as IntegrationExecutionContext;
  await executionHandler(invocationContext);

  expect(initializeContext).toHaveBeenCalledWith(invocationContext);

  expect(executionContext.graph.findAllEntitiesByType).toHaveBeenCalledWith(
    ACCOUNT_ENTITY_TYPE,
  );
  expect(executionContext.graph.findEntitiesByType).toHaveBeenCalledWith(
    AGENT_ENTITY_TYPE,
  );
  expect(executionContext.graph.findRelationshipsByType).toHaveBeenCalledWith(
    ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  );

  expect(executionContext.provider.getAccountDetails).toHaveBeenCalledTimes(1);
  expect(executionContext.provider.getServerAgents).toHaveBeenCalledTimes(2);

  // account, agents
  expect(executionContext.persister.processEntities).toHaveBeenCalledTimes(2);

  // account -HAS-> agents; agent -IDENTIFIED-> cve
  expect(executionContext.persister.processRelationships).toHaveBeenCalledTimes(
    2,
  );
  expect(
    executionContext.persister.publishPersisterOperations,
  ).toHaveBeenCalledTimes(1);
});
