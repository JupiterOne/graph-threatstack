import { IntegrationExecutionContext } from "@jupiterone/jupiter-managed-integration-sdk";
import ThreatStackClient from "./ThreatStackClient";
import { ThreatStackExecutionContext } from "./types";

export default function initializeContext(
  context: IntegrationExecutionContext,
): ThreatStackExecutionContext {
  return {
    ...context,
    ...context.clients.getClients(),
    provider: new ThreatStackClient(context.instance.config, context.logger),
  };
}
