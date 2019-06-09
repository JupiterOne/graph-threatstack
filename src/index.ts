import {
  IntegrationError,
  IntegrationInvocationConfig,
  IntegrationStepExecutionContext,
} from "@jupiterone/jupiter-managed-integration-sdk";

import initializeContext from "./initializeContext";
import invocationValidator from "./invocationValidator";
import synchronizeGraph from "./synchronizeGraph";
import fetchBatchOfAgents from "./threatstack/fetchBatchOfAgents";
import fetchBatchOfVulnerabilities from "./threatstack/fetchBatchOfVulnerabilities";

const invocationConfig: IntegrationInvocationConfig = {
  invocationValidator,
  integrationStepPhases: [
    {
      steps: [
        {
          name: "Fetch Online Agents",
          iterates: true,
          executionHandler: async (
            executionContext: IntegrationStepExecutionContext,
          ) => {
            const iterationState = executionContext.event.iterationState;
            if (!iterationState) {
              throw new IntegrationError(
                "Expected iterationState not found in event!",
              );
            }
            return fetchBatchOfAgents(
              await initializeContext(executionContext),
              iterationState,
              "online",
            );
          },
        },
      ],
    },
    {
      steps: [
        {
          name: "Fetch Offline Agents",
          iterates: true,
          executionHandler: async (
            executionContext: IntegrationStepExecutionContext,
          ) => {
            const iterationState = executionContext.event.iterationState;
            if (!iterationState) {
              throw new IntegrationError(
                "Expected iterationState not found in event!",
              );
            }
            return fetchBatchOfAgents(
              await initializeContext(executionContext),
              iterationState,
              "offline",
            );
          },
        },
      ],
    },
    {
      steps: [
        {
          name: "Fetch Vulnerabilities",
          iterates: true,
          executionHandler: async (
            executionContext: IntegrationStepExecutionContext,
          ) => {
            const iterationState = executionContext.event.iterationState;
            if (!iterationState) {
              throw new IntegrationError(
                "Expected iterationState not found in event!",
              );
            }
            return fetchBatchOfVulnerabilities(
              await initializeContext(executionContext),
              iterationState,
            );
          },
        },
      ],
    },
    {
      steps: [
        {
          name: "Synchronize Graph",
          executionHandler: synchronizeGraph,
        },
      ],
    },
  ],
};

export default invocationConfig;
