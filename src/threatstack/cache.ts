import { IntegrationCache } from "@jupiterone/jupiter-managed-integration-sdk";

import {
  ThreatStackAgent,
  ThreatStackAgentStatus,
  ThreatStackVulnerability,
  ThreatStackVulnerableServer,
} from "./types";

export interface ThreatStackAgentCacheEntry {
  key: string;
  data?: ThreatStackAgent;
}

export interface ThreatStackVulnerabilityCacheData {
  vulnerability: ThreatStackVulnerability;
  vulnerableServers: ThreatStackVulnerableServer[];
}

export interface ThreatStackVulnerabilityCacheEntry {
  key: string;
  data?: ThreatStackVulnerabilityCacheData;
}

export function createAgentCache(
  cache: IntegrationCache,
  agentStatus: ThreatStackAgentStatus,
) {
  const idsKey = `agentIds/${agentStatus}`;
  const entryKeyPrefix = `agents/${agentStatus}`;

  return {
    putIds: async (ids: string[]) => {
      await cache.putEntry({
        key: idsKey,
        data: ids,
      });
    },

    getIds: async (): Promise<string[]> => {
      const entry = await cache.getEntry(idsKey);
      return entry.data || [];
    },

    getEntries: async (
      keys: string[],
    ): Promise<ThreatStackAgentCacheEntry[]> => {
      return cache.getEntries(keys);
    },

    putEntries: async (entries: ThreatStackAgentCacheEntry[]) => {
      await cache.putEntries(entries);
    },

    putData: async (data: ThreatStackAgent) => {
      await cache.putEntry({
        key: `${entryKeyPrefix}/${data.id}`,
        data,
      });
    },

    getData: async (id: string) => {
      const entry = await cache.getEntry(`${entryKeyPrefix}/${id}`);
      if (entry.data) {
        return entry.data;
      } else {
        throw new Error(
          `Data not found in cache for '${entryKeyPrefix}/${id}', something is wrong`,
        );
      }
    },
  };
}

export function createVulnerabilityCache(cache: IntegrationCache) {
  const idsKey = "vulnIds";
  const entryKeyPrefix = "vulns";

  return {
    putIds: async (ids: string[]) => {
      await cache.putEntry({
        key: idsKey,
        data: ids,
      });
    },

    getIds: async (): Promise<string[]> => {
      const entry = await cache.getEntry(idsKey);
      return entry.data || [];
    },

    getEntries: async (
      keys: string[],
    ): Promise<ThreatStackVulnerabilityCacheEntry[]> => {
      return cache.getEntries(keys);
    },

    putEntries: async (entries: ThreatStackVulnerabilityCacheEntry[]) => {
      await cache.putEntries(entries);
    },

    putData: async (data: ThreatStackVulnerabilityCacheData) => {
      await cache.putEntry({
        key: `${entryKeyPrefix}/${data.vulnerability.cveNumber}`,
        data,
      });
    },

    getData: async (id: string) => {
      const entry = await cache.getEntry(`${entryKeyPrefix}/${id}`);
      if (entry.data) {
        return entry.data;
      } else {
        throw new Error(
          `Data not found in cache for '${entryKeyPrefix}/${id}', something is wrong`,
        );
      }
    },
  };
}
