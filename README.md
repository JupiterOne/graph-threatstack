# JupiterOne Managed Integration for Threat Stack

[![Build Status](https://travis-ci.org/JupiterOne/graph-threatstack.svg?branch=master)](https://travis-ci.org/JupterOne/graph-threatstack)

This JupiterOne integration connects to a Threat Stack account using a provided
API Auth token and ingests the Threat Stack server agents and the vulnerability
findings they identified.

## Development Environment

Integrations mutate the graph to reflect configurations and metadata from the
provider. Developing an integration involves:

1.  Establishing a secure connection to a provider API
1.  Fetching provider data and converting it to entities and relationships
1.  Collecting the existing set of entities and relationships already in the
    graph
1.  Performing a diff to determine which entites/relationships to
    create/update/delete
1.  Delivering create/update/delete operations to the persister to update the
    graph

Run the integration to see what happens.

Prerequisites:

1.  Install Docker and Docker Compose (both included in Docker for Mac installs)
1.  Install Node (Node Version Manager is recommended)
1.  Provide credentials in `.env`

Node:

1.  `yarn install`
1.  `yarn start:containers`
1.  `yarn start`

Activity is logged to the console indicating the operations produced and
processed. View raw data in the graph database using
[Graphexp](https://github.com/bricaud/graphexp).

Execute the integration again to see that there are no change operations
produced.

Restart the graph server to clear the data when you want to run the integration
with no existing data.

```sh
yarn start:containers
```

### Environment Variables

- `GRAPH_DB_ENDPOINT` - `"localhost"`

### Running tests

All tests must be written using Jest. Focus on testing provider API interactions
and conversion from provider data to entities and relationships.

To run tests locally:

```shell
yarn test
```

### Deployment

Managed integrations are deployed into the JupiterOne infrastructure by staff
engineers using internal projects that declare a dependency on the open source
integration NPM package. The package will be published by the JupiterOne team.

```shell
yarn build:publish
```
