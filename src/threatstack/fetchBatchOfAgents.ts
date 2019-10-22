import {
  IntegrationCacheEntry,
  IntegrationStepIterationState,
} from "@jupiterone/jupiter-managed-integration-sdk";

import { ResourceCacheState, ThreatStackExecutionContext } from "../types";
import ThreatStackClient from "./ThreatStackClient";
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
): Promise<IntegrationStepIterationState> {
  const cache = executionContext.clients.getCache();
  const resourceCache = cache.iterableCache<
    IntegrationCacheEntry,
    ResourceCacheState
  >(`${agentStatus}Agents`);

  const {
    instance: { config },
    logger,
  } = executionContext;

  const client = new ThreatStackClient(config, logger);

  let pagesProcessed = 0;
  let entryCount: number = iterationState.state.count || 0;
  let token = iterationState.state.token;

  do {
    const agents = await client.getServerAgents(agentStatus, token);
    entryCount = await resourceCache.putEntries(
      agents.agents.map(e => ({
        key: e.id,
        data: e,
      })),
    );

    token = agents.token;
    pagesProcessed++;
  } while (token && pagesProcessed < BATCH_PAGES);

  const finished = typeof token !== "string";
  await resourceCache.putState({ resourceFetchCompleted: finished });

  return {
    ...iterationState,
    finished,
    state: {
      token,
      limit: 100,
      pages: pagesProcessed,
      count: entryCount,
    },
  };
}
