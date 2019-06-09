import {
  IntegrationStepExecutionResult,
  IntegrationStepIterationState,
} from "@jupiterone/jupiter-managed-integration-sdk";

import { ThreatStackExecutionContext } from "../types";
import {
  createVulnerabilityCache,
  ThreatStackVulnerabilityCacheEntry,
} from "./cache";
import ThreatStackClient from "./client";
import { ThreatStackVulnerableServer } from "./types";

/**
 * The number of pages to process per iteration.
 */
const BATCH_PAGES = process.env.TS_VULNS_BATCH_PAGES
  ? Number(process.env.TS_VULNS_BATCH_PAGES)
  : 1;

/**
 * An iterating execution handler that loads ThreatStack vulnerabilities
 * `BATCH_PAGES` batches of 100, storing the raw response data in the
 * `IntegrationCache` for later processing in another step.
 *
 * This is necessary because ThreatStack limits API requests to 200/min across
 * the entire organization, leading to a need to spread requests over a period
 * of time that exceeds the execution time limits of the execution environment.
 *
 * This will also load the vulnerable servers for each vulnerability.
 */
export default async function fetchBatchOfVulnerabilities(
  executionContext: ThreatStackExecutionContext,
  iterationState: IntegrationStepIterationState,
): Promise<IntegrationStepExecutionResult> {
  const cache = createVulnerabilityCache(executionContext.clients.getCache());

  const {
    instance: { config },
    logger,
  } = executionContext;

  const client = new ThreatStackClient(config, logger);

  const cachedIds = iterationState.iteration > 0 ? (await cache.getIds())! : [];

  const cacheEntries: ThreatStackVulnerabilityCacheEntry[] = [];

  let pagesProcessed = 0;
  let token = iterationState.state.token;

  do {
    const vulnerabilitiesResponse = await client.getVulnerabilities(token);

    for (const vulnerability of vulnerabilitiesResponse.cves) {
      const vulnerableServers: ThreatStackVulnerableServer[] = [];

      let serversToken: string | null;
      do {
        const serversResponse = await client.getVulnerableServers(
          vulnerability.cveNumber,
        );
        vulnerableServers.push(...serversResponse.servers);
        serversToken = serversResponse.token;
      } while (serversToken);

      cachedIds.push(vulnerability.cveNumber);
      cacheEntries.push({
        key: vulnerability.cveNumber,
        data: {
          vulnerability,
          vulnerableServers,
        },
      });
    }

    token = vulnerabilitiesResponse.token;
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
