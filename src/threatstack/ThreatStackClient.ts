import fetch, { Response } from "node-fetch";
import PQueue from "p-queue";
import { URL } from "url";

import * as Hawk from "@hapi/hawk";
import {
  IntegrationError,
  IntegrationLogger,
} from "@jupiterone/jupiter-managed-integration-sdk";
import { AttemptContext, retry } from "@lifeomic/attempt";

import { ThreatStackIntegrationConfig } from "../types";
import {
  ThreatStackAgent,
  ThreatStackVulnerability,
  ThreatStackVulnerableServer,
} from "./types";

interface HawkHeaderOptions {
  credentials: {
    id: string;
    key: string;
    algorithm: string;
  };
  ext: string;
  contentType: string;
}

interface AgentsResponse {
  token: string | null;
  agents: ThreatStackAgent[];
}

interface VulnerabilitiesResponse {
  token: string | null;
  cves: ThreatStackVulnerability[];
}

interface VulnerableServersResponse {
  token: string | null;
  servers: ThreatStackVulnerableServer[];
}

export default class ThreatStackClient {
  private BASE_API_URL = `https://api.threatstack.com/v2`;

  private logger: IntegrationLogger;

  private requestQueue: PQueue;
  private headerOptions: HawkHeaderOptions;

  constructor(config: ThreatStackIntegrationConfig, logger: IntegrationLogger) {
    this.logger = logger;

    const credentials = {
      id: config.userId,
      key: config.apiKey,
      algorithm: "sha256",
    };

    this.headerOptions = {
      credentials,
      ext: config.orgId,
      contentType: "application/json",
    };

    // p-queue is helpful when all requests are running in a single process, or
    // there are subsequent processes that are considerate of how many requests
    // the previous process used, but in the case where API calls are made from
    // concurrent processes, we're going to need something a bit more
    // sophisticated.
    this.requestQueue = new PQueue({
      interval: 5000,
      intervalCap: 10,
    });
  }

  public async getServerAgents(
    status: string,
    token?: string,
  ): Promise<AgentsResponse> {
    return this.makeRequest<AgentsResponse>(
      `${this.BASE_API_URL}/agents?status=${status}`,
      token,
    );
  }

  public async getVulnerabilities(
    token?: string,
  ): Promise<VulnerabilitiesResponse> {
    return this.makeRequest<VulnerabilitiesResponse>(
      `${this.BASE_API_URL}/vulnerabilities`,
      token,
    );
  }

  public async getVulnerableServers(
    cveNumber: string,
    token?: string,
  ): Promise<VulnerableServersResponse> {
    return this.makeRequest<VulnerableServersResponse>(
      `${this.BASE_API_URL}/vulnerabilities/${cveNumber}/servers`,
      token,
    );
  }

  private async makeRequest<T>(
    resourceUrl: string,
    token?: string,
  ): Promise<T> {
    const paginatedUrl = new URL(resourceUrl);
    if (token) {
      paginatedUrl.searchParams.append("token", token);
    }

    const url = paginatedUrl.toString();

    return retry(
      async () => {
        return this.requestQueue.add(async () => {
          const { header } = Hawk.client.header(url, "GET", this.headerOptions);

          let response: Response | undefined;
          try {
            response = await fetch(url, {
              headers: {
                "Content-Type": "application/json",
                Authorization: header,
              },
            });
          } catch (err) {
            throw new IntegrationError(err);
          }
          if (response.status === 200) {
            const json = await response.json();
            this.logger.trace(
              {
                url,
                rateLimitRemaining: response.headers.get(
                  "x-rate-limit-remaining",
                ),
              },
              "Fetch completed",
            );
            return (json as unknown) as T;
          } else {
            throw new IntegrationError({
              message: response.statusText,
              statusCode: response.status,
            });
          }
        });
      },
      {
        delay: 5000,
        factor: 1.2,
        maxAttempts: 15,
        handleError(err: Error, context: AttemptContext) {
          const error = err as IntegrationError;
          const code = error.statusCode;
          if (code !== 429 && code !== 500) {
            context.abort();
          }
        },
      },
    );
  }
}
