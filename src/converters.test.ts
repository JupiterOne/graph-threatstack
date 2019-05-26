import { createAccountRelationships, createAgentEntities } from "./converters";
import { ThreatStackAgent } from "./ThreatStackClient";
import {
  ACCOUNT_AGENT_RELATIONSHIP_TYPE,
  ACCOUNT_ENTITY_CLASS,
  ACCOUNT_ENTITY_TYPE,
  AGENT_ENTITY_CLASS,
  AGENT_ENTITY_TYPE,
  ThreatStackAccountEntity,
} from "./types";
import getTime from "./util/getTime";
import { normalizeHostname } from "./util/normalizeHostname";

export const accountEntity: ThreatStackAccountEntity = {
  _key: "threatstack:account:123456",
  _type: ACCOUNT_ENTITY_TYPE,
  _class: ACCOUNT_ENTITY_CLASS,
  accountId: "12a345b6c78d9e00fd99e",
  name: "my-ts-org",
};

export const agent: ThreatStackAgent = {
  id: "8b0f0b28-7fce-11e9-a425-99cdd68cb067",
  instanceId: "i-0d0f1f32bea26a881",
  status: "online",
  createdAt: "2019-05-26T15:54:28.452Z",
  lastReportedAt: "2019-05-26T16:04:48.376Z",
  version: "1.9.0",
  name: "ip-10-50-140-117",
  description: "",
  hostname: "ip-10-50-140-117",
  ipAddresses: {
    private: ["10.50.140.117"],
    link_local: ["fe80::4d8:28ff:feed:7692"],
    public: ["34.195.165.153"],
  },
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
  agentType: "investigate",
  osVersion: "amzn 2018.03",
  kernel: "4.14.114-83.126.amzn1.x86_64",
};

export const agents: ThreatStackAgent[] = [agent];

test("createAccountRelationships", () => {
  const sensorEntities = createAgentEntities(agents);

  expect(
    createAccountRelationships(
      accountEntity,
      sensorEntities,
      ACCOUNT_AGENT_RELATIONSHIP_TYPE,
    ),
  ).toEqual([
    {
      _class: "HAS",
      _fromEntityKey: accountEntity._key,
      _key: `${accountEntity._key}_has_${sensorEntities[0]._key}`,
      _toEntityKey: sensorEntities[0]._key,
      _type: ACCOUNT_AGENT_RELATIONSHIP_TYPE,
    },
  ]);
});

test("createAgentEntities", () => {
  expect(createAgentEntities(agents)).toEqual([
    {
      _key: `threatstack:agent:${agent.id}`,
      _class: AGENT_ENTITY_CLASS,
      _type: AGENT_ENTITY_TYPE,
      displayName: agent.name,
      id: agent.id,
      instanceId: agent.instanceId,
      status: agent.status,
      active: true,
      version: agent.version,
      name: agent.name,
      description: agent.description,
      hostname: normalizeHostname(agent.hostname),
      ipAddresses: ["34.195.165.153", "10.50.140.117"],
      publicIpAddress: ["34.195.165.153"],
      privateIpAddress: ["10.50.140.117"],
      macAddress: ["fe80::4d8:28ff:feed:7692"],
      agentType: agent.agentType,
      kernel: agent.kernel,
      osVersion: agent.osVersion,
      createdAt: getTime(agent.createdAt),
      lastReportedAt: getTime(agent.lastReportedAt),
      createdOn: getTime(agent.createdAt),
      function: ["FIM", "activity-monitor", "vulnerability-scan"],
    },
  ]);
});
