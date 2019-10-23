import {
  IntegrationCacheEntry,
  IntegrationStepIterationState,
} from "@jupiterone/jupiter-managed-integration-sdk";

import {
  ResourceCacheState,
  ThreatStackExecutionContext,
  ThreatStackVulnerabilityCacheData,
} from "../types";
import ThreatStackClient from "./ThreatStackClient";
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
): Promise<IntegrationStepIterationState> {
  const cache = executionContext.clients.getCache();
  const resourceCache = cache.iterableCache<
    IntegrationCacheEntry,
    ResourceCacheState
  >("vulnerabilities");

  const {
    instance: { config },
    logger,
  } = executionContext;

  const client = new ThreatStackClient(config, logger);

  let pagesProcessed = 0;
  let entryCount: number = iterationState.state.count || 0;
  let token = iterationState.state.token;

  do {
    const vulnerabilitiesResponse = await client.getVulnerabilities(token);

    const cacheData: ThreatStackVulnerabilityCacheData[] = [];
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

      cacheData.push({
        vulnerability,
        vulnerableServers,
      });
    }

    entryCount = await resourceCache.putEntries(
      cacheData.map(e => ({ key: e.vulnerability.cveNumber, data: e })),
    );

    token = vulnerabilitiesResponse.token;
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
