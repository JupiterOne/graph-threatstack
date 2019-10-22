import {
  IntegrationError,
  IntegrationInvocationConfig,
  IntegrationStepExecutionContext,
  IntegrationStepInvocationEvent,
} from "@jupiterone/jupiter-managed-integration-sdk";

import initializeContext from "./initializeContext";
import invocationValidator from "./invocationValidator";
import synchronizeGraph from "./synchronizeGraph";
import fetchBatchOfAgents from "./threatstack/fetchBatchOfAgents";
import fetchBatchOfVulnerabilities from "./threatstack/fetchBatchOfVulnerabilities";

const invocationConfig: IntegrationInvocationConfig = {
  instanceConfigFields: {
    orgName: {
      type: "string",
    },
    orgId: {
      type: "string",
    },
    userId: {
      type: "string",
    },
    apiKey: {
      type: "string",
      mask: true,
    },
  },

  invocationValidator,

  integrationStepPhases: [
    {
      steps: [
        {
          id: "fetch-agents-online",
          name: "Fetch Online Agents",
          iterates: true,
          executionHandler: async (
            executionContext: IntegrationStepExecutionContext,
          ) => {
            return fetchBatchOfAgents(
              await initializeContext(executionContext),
              getIterationState(executionContext.event),
              "online",
            );
          },
        },
      ],
    },
    {
      steps: [
        {
          id: "fetch-agents-offline",
          name: "Fetch Offline Agents",
          iterates: true,
          executionHandler: async (
            executionContext: IntegrationStepExecutionContext,
          ) => {
            return fetchBatchOfAgents(
              await initializeContext(executionContext),
              getIterationState(executionContext.event),
              "offline",
            );
          },
        },
      ],
    },
    {
      steps: [
        {
          id: "fetch-vulns",
          name: "Fetch Vulnerabilities",
          iterates: true,
          executionHandler: async (
            executionContext: IntegrationStepExecutionContext,
          ) => {
            return fetchBatchOfVulnerabilities(
              await initializeContext(executionContext),
              getIterationState(executionContext.event),
            );
          },
        },
      ],
    },
    {
      steps: [
        {
          id: "synch",
          name: "Synchronize Graph",
          executionHandler: synchronizeGraph,
        },
      ],
    },
  ],
};

function getIterationState(event: IntegrationStepInvocationEvent) {
  const iterationState = event.iterationState;
  if (!iterationState) {
    throw new IntegrationError("Expected iterationState not found in event!");
  } else {
    return iterationState;
  }
}

export default invocationConfig;
