import {
  IntegrationInstanceConfigError,
  IntegrationValidationContext,
} from "@jupiterone/jupiter-managed-integration-sdk";

export default async function invocationValidator(
  context: IntegrationValidationContext,
) {
  const { config } = context.instance;

  if (!config) {
    throw new IntegrationInstanceConfigError("configuration not found");
  }

  const { apiKey, orgId, orgName, userId } = config;

  if (!(orgId && orgName && userId && apiKey)) {
    throw new IntegrationInstanceConfigError(
      "Instance configuration requires all of { orgId, orgName, userId, apiKey }",
    );
  }
}
