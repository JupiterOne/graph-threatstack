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

  if (!orgId) {
    throw new IntegrationInstanceConfigError(
      `Missing Organization ID in configuration (accountId=${accountId})`,
    );
  }

  if (!orgName) {
    throw new IntegrationInstanceConfigError(
      `Missing Organization Name in configuration (accountId=${accountId})`,
    );
  }

  if (!userId) {
    throw new IntegrationInstanceConfigError(
      `Missing User ID in configuration (accountId=${accountId})`,
    );
  }

  if (!apiKey) {
    throw new IntegrationInstanceConfigError(
      `Missing API Key in configuration (accountId=${accountId})`,
    );
  }
}
