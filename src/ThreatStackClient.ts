import * as axios from "axios";
import { throttleAdapterEnhancer } from "axios-extensions";

import * as Hawk from "@hapi/hawk";
import {
  IntegrationError,
  IntegrationInstanceAuthenticationError,
  IntegrationInstanceAuthorizationError,
  IntegrationLogger,
} from "@jupiterone/jupiter-managed-integration-sdk";
import { AttemptContext, retry } from "@lifeomic/attempt";

import {
  ACCOUNT_ENTITY_CLASS,
  ACCOUNT_ENTITY_TYPE,
  PROVIDER_NAME,
  ThreatStackAccountEntity,
  ThreatStackIntegrationConfig,
} from "./types";
import * as axiosUtil from "./util/axios-util";

interface Page<T> {
  token: string;
  agents?: T[];
  cves?: T[];
  servers?: T[];
}

interface HawkHeaderOptions {
  credentials: {
    id: string;
    key: string;
    algorithm: string;
  };
  ext: string;
  contentType: string;
}

export interface ThreatStackAgentIpAddresses {
  private: string | string[];
  link_local: string | string[];
  public: string | string[];
}

export interface ThreatStackAgentTags {
  source?: string | null;
  key?: string | null;
  value?: string | null;
}

export interface ThreatStackAgent {
  id: string;
  instanceId?: string | null;
  status: string;
  createdAt: string;
  lastReportedAt: string;
  version: string;
  name?: string | null;
  description?: string | null;
  hostname: string;
  ipAddresses?: ThreatStackAgentIpAddresses | null;
  tags?: ThreatStackAgentTags[] | null;
  agentType: string;
  kernel?: string | null;
  osVersion?: string | null;
}

export interface ThreatStackVulnerability {
  cveNumber: string;
  reportedPackage: string;
  systemPackage: string;
  vectorType: string;
  severity: string;
  isSuppressed: boolean;
}

export interface ThreatStackVulnerableServer {
  agentId: string;
  hostname?: string | null;
}

export default class ThreatStackClient {
  private axiosInstance: axios.AxiosInstance;
  private BASE_API_URL: string;
  private logger: IntegrationLogger;
  private options: HawkHeaderOptions;
  private orgName: string;
  private orgId: string;
  private provider: string;

  constructor(config: ThreatStackIntegrationConfig, logger: IntegrationLogger) {
    this.BASE_API_URL = `https://api.threatstack.com/v2`;
    this.logger = logger;
    this.orgId = config.orgId;
    this.orgName = config.orgName;
    this.provider = "Threat Stack";

    const credentials = {
      id: config.userId,
      key: config.apiKey,
      algorithm: "sha256",
    };

    const headerOptions: HawkHeaderOptions = {
      credentials,
      ext: config.orgId,
      contentType: "application/json",
    };

    this.options = headerOptions;

    this.axiosInstance = axiosUtil.createInstance(
      {
        baseURL: this.BASE_API_URL,
        adapter: throttleAdapterEnhancer(
          axios.default.defaults.adapter as axios.AxiosAdapter,
          { threshold: 2 * 1000 },
        ),
      },
      logger,
    );
  }

  public getAccountDetails(): ThreatStackAccountEntity {
    return {
      _key: `${PROVIDER_NAME}:account:${this.orgId}`,
      _type: ACCOUNT_ENTITY_TYPE,
      _class: ACCOUNT_ENTITY_CLASS,
      accountId: this.orgId,
      name: this.orgName,
      displayName: `Threat Stack - ${this.orgName}`,
    };
  }

  public async getServerAgents(
    status: string,
  ): Promise<ThreatStackAgent[] | undefined> {
    return await this.collectAllPages<ThreatStackAgent>(
      "agents",
      `status=${status}`,
    );
  }

  public async getVulnerabilities(
    status?: string,
  ): Promise<ThreatStackVulnerability[] | undefined> {
    return await this.collectAllPages<ThreatStackVulnerability>(
      "vulnerabilities",
      status ? `status=${status}` : undefined,
    );
  }

  public async getVulnerableServers(
    cve: string,
  ): Promise<ThreatStackVulnerableServer[] | undefined> {
    return await this.collectAllPages<ThreatStackVulnerableServer>(
      `vulnerabilities/${cve}/servers`,
    );
  }

  private async forEachPage<T>(
    firstUri: string,
    params: string | null | undefined,
    eachFn: (page: Page<T>) => void,
  ) {
    const pagePrefix = params
      ? `${this.BASE_API_URL}/${firstUri}?${params}&`
      : `${this.BASE_API_URL}/${firstUri}?`;

    let nextPageUrl: string | null = params
      ? `${this.BASE_API_URL}/${firstUri}?${params}`
      : `${this.BASE_API_URL}/${firstUri}`;

    do {
      nextPageUrl = await retry(
        async () => {
          const { header } = Hawk.client.header(
            nextPageUrl,
            "GET",
            this.options,
          );
          const response = await this.axiosInstance.get<Page<T>>(nextPageUrl!, {
            headers: {
              "Content-Type": "application/json",
              Authorization: header,
            },
          });

          const page: any = response.data;
          eachFn(page);
          return page.token ? `${pagePrefix}token=${page.token}` : null;
        },
        {
          initialDelay: 1000,
          delay: 5000,
          factor: 1.2,
          maxAttempts: 15,
          handleError(err: Error, context: AttemptContext) {
            const axiosErr = err as axios.AxiosError;
            if (axiosErr.response) {
              const code = axiosErr.response.status;
              if (code !== 429 && code !== 500) {
                context.abort();
              }
            }
          },
        },
      );
    } while (nextPageUrl);
  }

  private async collectAllPages<T>(
    firstUri: string,
    params?: string,
  ): Promise<T[] | undefined> {
    try {
      const results: T[] = [];
      const key = firstUri.includes("servers")
        ? "servers"
        : firstUri.includes("vulnerabilities")
        ? "cves"
        : "agents";
      this.logger.trace(`Fetching ${this.provider} ${firstUri}...`);
      await this.forEachPage<T>(firstUri, params, (page: Page<T>) => {
        for (const item of page[key] || []) {
          results.push(item);
        }
      });
      this.logger.trace(`Fetched ${this.provider} ${firstUri}`);
      return results;
    } catch (err) {
      const code = err.response.status;
      if (code === 401) {
        throw new IntegrationInstanceAuthenticationError(err);
      } else if (code === 403) {
        throw new IntegrationInstanceAuthorizationError(err, firstUri);
      } else if (code === 500 || code === 429) {
        this.logger.warn(
          { err },
          `Server error from ${this.provider} while retrieving ${firstUri}`,
        );
        return undefined;
      } else {
        throw new IntegrationError({
          cause: err,
          expose: false,
          message: `Unable to retrieve ${this.BASE_API_URL}/${firstUri}`,
        });
      }
    }
  }
}
