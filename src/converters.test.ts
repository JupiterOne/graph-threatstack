import { RelationshipDirection } from "@jupiterone/jupiter-managed-integration-sdk";

import {
  createAccountRelationships,
  createAgentEntities,
  createAgentFindingMappedRelationship,
} from "./converters";
import {
  ThreatStackAgent,
  ThreatStackVulnerability,
} from "./ThreatStackClient";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_CLASS,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_CLASS,
  AGENT_ENTITY_TYPE,
  ThreatStackAccountEntity,
} from "./types";
import getCVE from "./util/getCVE";
import getTime from "./util/getTime";
import { normalizeHostname } from "./util/normalizeHostname";

export const accountEntity: ThreatStackAccountEntity = {
  _key: "threatstack:account:123456",
  _type: ACCOUNT_ENTITY_TYPE,
  _class: ACCOUNT_ENTITY_CLASS,
  accountId: "12a345b6c78d9e00fd99e",
  name: "my-ts-org",
};

export const agentBase: ThreatStackAgent = {
  id: "8b0f0b28-7fce-11e9-a123-99cdd68cb066",
  status: "online",
  createdAt: "2019-05-26T15:54:28.452Z",
  lastReportedAt: "2019-05-26T16:04:48.376Z",
  version: "1.9.0",
  name: "ip-10-50-140-117",
  description: "",
  hostname: "ip-10-50-140-117",
  agentType: "investigate",
  osVersion: "amzn 2018.03",
  kernel: "4.14.114-83.126.amzn1.x86_64",
};

export const agentWithoutName: ThreatStackAgent = {
  ...agentBase,
  id: "8b0f0b28-7fce-11e9-a123-99cdd68cb067",
  name: undefined,
};

export const agentWithIp: ThreatStackAgent = {
  ...agentBase,
  id: "8b0f0b28-7fce-11e9-a123-99cdd68cb068",
  instanceId: "i-0d0f1f32bea26a881",
  ipAddresses: {
    private: ["10.50.140.117"],
    link_local: ["fe80::4d8:28ff:feed:7692"],
    public: ["34.195.165.153"],
  },
};

export const agentWithTags: ThreatStackAgent = {
  ...agentBase,
  id: "8b0f0b28-7fce-11e9-a123-99cdd68cb069",
  instanceId: "i-0d0f1f32bea26a881",
  tags: [
    {
      source: "ec2",
      key: "Environment",
      value: "internal",
    },
    {
      source: "ec2",
      key: "EcsCluster",
      value: "default",
    },
    {
      source: "ec2",
      key: "Project",
      value: "ecs-cluster",
    },
    {
      source: "ec2",
      key: "Name",
      value: "ecs-cluster-primary",
    },
    {
      key: "classification",
      value: "internal",
    },
  ],
};

export const agents: ThreatStackAgent[] = [
  agentBase,
  agentWithoutName,
  agentWithIp,
  agentWithTags,
];

export const cves: ThreatStackVulnerability[] = [
  {
    cveNumber: "CVE-2018-19932",
    reportedPackage: "binutils 2.25.1",
    systemPackage: "binutils 2.25.1-31.base.66.amzn1.x86_64",
    vectorType: "network",
    severity: "medium",
    isSuppressed: false,
  },
  {
    cveNumber: "CVE-2018-1000876",
    reportedPackage: "binutils 2.25.1",
    systemPackage: "binutils 2.25.1-31.base.66.amzn1.x86_64",
    vectorType: "local",
    severity: "medium",
    isSuppressed: false,
  },
];

export const vulnerableServers = [
  {
    agentId: "8b0f0b28-7fce-11e9-a123-99cdd68cb066",
  },
  {
    agentId: "8b0f0b28-7fce-11e9-a123-99cdd68cb067",
  },
  {
    agentId: "8b0f0b28-7fce-11e9-a123-99cdd68cb068",
  },
  {
    agentId: "8b0f0b28-7fce-11e9-a123-99cdd68cb069",
  },
];

test("createAccountRelationships", () => {
  const agentEntities = createAgentEntities(agents);

  expect(
    createAccountRelationships(
      accountEntity,
      agentEntities,
      ACCOUNT_AGENT_RELATIONSHIP_TYPE,
    ),
  ).toEqual([
    {
      _class: "HAS",
      _fromEntityKey: accountEntity._key,
      _key: `${accountEntity._key}|has|${agentEntities[0]._key}`,
      _toEntityKey: agentEntities[0]._key,
      _type: ACCOUNT_AGENT_RELATIONSHIP_TYPE,
      displayName: "HAS",
    },
    {
      _class: "HAS",
      _fromEntityKey: accountEntity._key,
      _key: `${accountEntity._key}|has|${agentEntities[1]._key}`,
      _toEntityKey: agentEntities[1]._key,
      _type: ACCOUNT_AGENT_RELATIONSHIP_TYPE,
      displayName: "HAS",
    },
    {
      _class: "HAS",
      _fromEntityKey: accountEntity._key,
      _key: `${accountEntity._key}|has|${agentEntities[2]._key}`,
      _toEntityKey: agentEntities[2]._key,
      _type: ACCOUNT_AGENT_RELATIONSHIP_TYPE,
      displayName: "HAS",
    },
    {
      _class: "HAS",
      _fromEntityKey: accountEntity._key,
      _key: `${accountEntity._key}|has|${agentEntities[3]._key}`,
      _toEntityKey: agentEntities[3]._key,
      _type: ACCOUNT_AGENT_RELATIONSHIP_TYPE,
      displayName: "HAS",
    },
  ]);
});

test("createAgentEntities", () => {
  const baseAgentEntity = {
    _key: `threatstack:agent:${agentBase.id}`,
    _class: AGENT_ENTITY_CLASS,
    _type: AGENT_ENTITY_TYPE,
    displayName: agentBase.name,
    id: agentBase.id,
    status: agentBase.status,
    active: true,
    version: agentBase.version,
    name: agentBase.name,
    description: agentBase.description,
    hostname: normalizeHostname(agents[0].hostname),
    ipAddresses: [],
    agentType: agentBase.agentType,
    kernel: agentBase.kernel,
    osVersion: agentBase.osVersion,
    createdAt: getTime(agentBase.createdAt),
    lastReportedAt: getTime(agentBase.lastReportedAt),
    createdOn: getTime(agentBase.createdAt),
    function: ["FIM", "activity-monitor", "vulnerability-scan"],
  };
  expect(createAgentEntities(agents)).toEqual([
    baseAgentEntity,
    {
      ...baseAgentEntity,
      _key: `threatstack:agent:${agentWithoutName.id}`,
      id: agentWithoutName.id,
      displayName: agentWithoutName.hostname,
      name: undefined,
    },
    {
      ...baseAgentEntity,
      _key: `threatstack:agent:${agentWithIp.id}`,
      instanceId: "i-0d0f1f32bea26a881",
      id: agentWithIp.id,
      ipAddresses: ["34.195.165.153", "10.50.140.117"],
      publicIpAddress: ["34.195.165.153"],
      privateIpAddress: ["10.50.140.117"],
      macAddress: ["fe80::4d8:28ff:feed:7692"],
    },
    {
      ...baseAgentEntity,
      _key: `threatstack:agent:${agentWithTags.id}`,
      instanceId: "i-0d0f1f32bea26a881",
      id: agentWithTags.id,
    },
  ]);
});

test("createAgentFindingMappedRelationship", () => {
  const agent = createAgentEntities(agents)[0];
  const cve = getCVE(cves[0].cveNumber, cves[0]);
  const agentKey = `threatstack:agent:${agentBase.id}`;
  const cveKey = "cve-2018-19932";
  expect(createAgentFindingMappedRelationship(agent, cve)).toEqual({
    _key: `${agentKey}|identified|${cveKey}`,
    _type: `threatstack_agent_identified_vulnerability`,
    _class: "IDENTIFIED",
    displayName: "IDENTIFIED",
    _mapping: {
      sourceEntityKey: agentKey,
      relationshipDirection: RelationshipDirection.FORWARD,
      targetFilterKeys: [["_type", "_key"]],
      targetEntity: cve,
    },
  });
});
