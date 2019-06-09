import {
  IntegrationStepExecutionResult,
  IntegrationStepIterationState,
} from "@jupiterone/jupiter-managed-integration-sdk";

import { ThreatStackExecutionContext } from "../types";
import { createAgentCache, ThreatStackAgentCacheEntry } from "./cache";
import ThreatStackClient from "./client";
import { ThreatStackAgentStatus } from "./types";

/**
 * The number of pages to process per iteration.
 */
const BATCH_PAGES = process.env.TS_AGENTS_BATCH_PAGES
  ? Number(process.env.TS_AGENTS_BATCH_PAGES)
  : 1;

/**
 * An iterating execution handler that loads ThreatStack agents `BATCH_PAGES`
 * batches of 100, storing the raw response data in the `IntegrationCache` for
 * later processing in another step.
 *
 * This is necessary because ThreatStack limits API requests to 200/min across
 * the entire organization, leading to a need to spread requests over a period
 * of time that exceeds the execution time limits of the execution environment.
 */
export default async function fetchBatchOfAgents(
  executionContext: ThreatStackExecutionContext,
  iterationState: IntegrationStepIterationState,
  agentStatus: ThreatStackAgentStatus,
): Promise<IntegrationStepExecutionResult> {
  const cache = createAgentCache(
    executionContext.clients.getCache(),
    agentStatus,
  );

  const {
    instance: { config },
    logger,
  } = executionContext;

  const client = new ThreatStackClient(config, logger);

  const cachedIds = iterationState.iteration > 0 ? (await cache.getIds())! : [];

  const cacheEntries: ThreatStackAgentCacheEntry[] = [];

  let pagesProcessed = 0;
  let token = iterationState.state.token;

  do {
    const agents = await client.getServerAgents(agentStatus, token);

    for (const agent of agents.agents) {
      cachedIds.push(agent.id);
      cacheEntries.push({
        key: agent.id,
        data: agent,
      });
    }

    token = agents.token;
    pagesProcessed++;
  } while (token && pagesProcessed < BATCH_PAGES);

  await Promise.all([cache.putIds(cachedIds), cache.putEntries(cacheEntries)]);

  return {
    iterationState: {
      ...iterationState,
      finished: typeof token !== "string",
      state: {
        token,
        limit: 100,
        pages: pagesProcessed,
        count: cachedIds.length,
      },
    },
  };
}
