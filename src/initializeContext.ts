import { IntegrationExecutionContext } from "@jupiterone/jupiter-managed-integration-sdk";
import { ThreatStackExecutionContext } from "./types";

export default function initializeContext(
  context: IntegrationExecutionContext,
): ThreatStackExecutionContext {
  return {
    ...context,
    ...context.clients.getClients(),
  };
}
