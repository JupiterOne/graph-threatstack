# Threat Stack

## Overview

JupiterOne provides a managed integration with Threat Stack. The integration
connects directly to Threat Stack APIs to obtain agents and vulnerability
findings data. Customers authorize access by creating an API Key in their target
Threat Stack account and providing that credential to JupiterOne.

## Threat Stack + JupiterOne Integration Benefits

- Visualize Threat Stack agents in the JupiterOne graph.
- Map Threat Stack agents to aws instances or servers they protect in your JupiterOne account.
- Map Threat Stack agents to cves they identify in your JupiterOne
- Monitor changes to Threat Stack agents using JupiterOne alerts.

## How it Works

- JupiterOne periodically fetches Threat Stack agents to update the graph.
- Write JupiterOne queries to review and monitor updates to the graph.
- Configure alerts to take action when the JupiterOne graph changes.

## Requirements

- JupiterOne requires the name and id of your Threat Stack organization. JupiterOne also 
requires the user id and API key of a configured application key.
- You must have permission in JupiterOne to install new integrations.

## Integration Instance Configuration

The integration is triggered by an event containing the information for a
specific integration instance.

The integration instance configuration requires the following three parameters
for API authentication:

Go to **Settings > Application Keys** from the web console of your Threat Stack
account, then find the following three values under **REST API Key**, copy/paste
each of them into your integration configuration screen in JupiterOne.

- **Organization Name** (`orgName`)
- **Organization ID** (`orgId`)
- **User ID** (`userId`)
- **API Key** (`apiKey`)

## Entities

The following entity resources are ingested when the integration runs:

| Example Entity Resource | \_type : \_class of the Entity    |
| ----------------------- | --------------------------------- |
| Account                 | `threatstack_account` : `Account` |
| Threat Stack Agent      | `threatstack_agent` : `HostAgent` |

## Relationships

The following relationships are created/mapped:

| Relationships                                     |
| ------------------------------------------------- |
| `threatstack_account` **HAS** `threatstack_agent` |
| `threatstack_agent` **PROTECTS** `aws_instance`   |
| `threatstack_agent` **PROTECTS** `server`         |
| `threatstack_agent` **IDENTIFIED** `cve`          |
