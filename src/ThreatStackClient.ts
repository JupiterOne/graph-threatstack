import * as axios from "axios";

import * as Hawk from "@hapi/hawk";
import {
  IntegrationInstanceAuthenticationError,
  IntegrationLogger,
} from "@jupiterone/jupiter-managed-integration-sdk";

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

export default class ThreatStackClient {
  private axiosInstance: axios.AxiosInstance;
  private BASE_API_URL: string;
  private logger: IntegrationLogger;
  private options: HawkHeaderOptions;
  private orgName: string;
  private orgId: string;

  constructor(config: ThreatStackIntegrationConfig, logger: IntegrationLogger) {
    this.BASE_API_URL = `https://api.threatstack.com/v2`;
    this.logger = logger;
    this.orgId = config.orgId;
    this.orgName = config.orgName;

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
    };
  }

  public async getServerAgents(status: string): Promise<ThreatStackAgent[]> {
    try {
      this.logger.trace("Fetching Threat Stack server agents...");
      const result = await this.collectAllPages<ThreatStackAgent>(
        "agents",
        `status=${status}`,
      );
      this.logger.trace({}, "Fetched Threat Stack server agents");
      return result;
    } catch (err) {
      const code = err.response.status;
      if (code === 401 || code === 403) {
        throw new IntegrationInstanceAuthenticationError(err);
      } else {
        throw new Error("Unable to retrieve Threat Stack server agents");
      }
    }
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

    while (nextPageUrl) {
      const { header } = Hawk.client.header(nextPageUrl, "GET", this.options);
      const response = await this.axiosInstance.get<Page<T>>(nextPageUrl, {
        headers: {
          "Content-Type": "application/json",
          Authorization: header,
        },
      });

      const page: any = response.data;
      eachFn(page);
      nextPageUrl = page.token ? `${pagePrefix}token=${page.token}` : null;
    }
  }

  private async collectAllPages<T>(
    firstUri: string,
    params?: string,
  ): Promise<T[]> {
    const results: T[] = [];

    await this.forEachPage<T>(firstUri, params, (page: Page<T>) => {
      for (const item of page.agents || []) {
        results.push(item);
      }
    });

    return results;
  }
}
