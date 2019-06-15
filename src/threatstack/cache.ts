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

export interface ThreatStackDataCache<E, D> {
  putIds: (ids: string[]) => Promise<void>;
  getIds: () => Promise<string[]>;
  getData: (key: string) => Promise<D>;
  getEntries: (keys: string[]) => Promise<E[]>;
  putEntries: (entries: E[]) => Promise<void>;
}

export function createAgentCache(
  cache: IntegrationCache,
  agentStatus: ThreatStackAgentStatus,
): ThreatStackDataCache<ThreatStackAgentCacheEntry, ThreatStackAgent> {
  const idsKey = `agentIds/${agentStatus}`;

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

    getData: async (key: string) => {
      const entry = await cache.getEntry(key);
      if (entry.data) {
        return entry.data;
      } else {
        throw new Error(
          `Data not found in cache for '${key}', something is wrong`,
        );
      }
    },

    getEntries: async (keys: string[]) => {
      return cache.getEntries(keys);
    },

    putEntries: async (entries: ThreatStackAgentCacheEntry[]) => {
      await cache.putEntries(entries);
    },
  };
}

export function createVulnerabilityCache(
  cache: IntegrationCache,
): ThreatStackDataCache<
  ThreatStackVulnerabilityCacheEntry,
  ThreatStackVulnerabilityCacheData
> {
  const idsKey = "vulnIds";

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

    getData: async (key: string) => {
      const entry = await cache.getEntry(key);
      if (entry.data) {
        return entry.data;
      } else {
        throw new Error(
          `Data not found in cache for '${key}', something is wrong`,
        );
      }
    },

    getEntries: async (keys: string[]) => {
      return cache.getEntries(keys);
    },

    putEntries: async (entries: ThreatStackVulnerabilityCacheEntry[]) => {
      await cache.putEntries(entries);
    },
  };
}
