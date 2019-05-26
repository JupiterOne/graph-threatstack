import {
  IntegrationExecutionContext,
  IntegrationInstanceConfigError,
  IntegrationInvocationEvent,
} from "@jupiterone/jupiter-managed-integration-sdk";
import { ThreatStackIntegrationConfig } from "./types";

export default async function invocationValidator(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
) {
  const { accountId, config } = context.instance;
  const instanceConfig = config as ThreatStackIntegrationConfig;

  if (!instanceConfig) {
    throw new IntegrationInstanceConfigError(
      `Threat Stack configuration not found (accountId=${accountId})`,
    );
  }

  const { apiKey, orgId, orgName, userId } = instanceConfig;

  if (!(orgId && orgName && userId && apiKey)) {
    throw new IntegrationInstanceConfigError(
      "Instance configuration requires all of { orgId, orgName, userId, apiKey }",
    );
  }
}
