# Local running for Orchestration API

This directory contains a wrapper for running the orchestration API locally without an AWS environment.

It can be used to test code changes quickly and with a debugger,
but cannot be used to fully test changes involving AWS components.

## How it works

The local-running app runs a [Javalin](https://javalin.io/) webserver which simulates the API Gateway integration,
transforming incoming requests to lambda handler invocations.

See [LocalOrchestrationApi.java](src/main/java/uk/gov/di/orchestration/local/LocalOrchestrationApi.java) for the mapping.

It runs the OIDC API as well as the Auth, IPV and Doc Checking APIs on the same server.

## How to use

### Prerequisites

The `orch-stubs` and `relying-party-stub` repos will need to be checked out (or symlinked)
at the same level as `authentication-api`, and the containers will be built from the current branch:

```
<dev workspace>
├─ authentication-api/
├─ orch-stubs/
└─ relying-party-stub/
```

### Basic usage

The simplest way is to run `docker compose up` in this directory. This will spin up a number of containers:

- `aws` - Localstack instance for SSM, KMS, and SQS dependencies
- `redis` - Redis container for remaining redis dependencies
- `dynamodb` - DynamoDB container for DynamoDB tables
- `relying-party-stub` - RP stub for starting journeys, running on [http://localhost:4000]
- `orchestration-api` - Orchestration API, running on [http://localhost:4400]
- `orchestration-stubs` - Auth, IPV, SPOT and AIS stubs running on [http://localhost:4401]

The RP stub will run at [http://localhost:4000] and journeys can be started there.

Standard docker compose commands can be used to rebuild containers when needed,
e.g. `docker compose build orchestration-api`.

### Debugging

#### Orchestration API debugging

Orchestration API exposes a debug port at `localhost:5400` for use with your favourite Java debugger.

In IntelliJ, you can set up a 'Remote JVM Debug' debug configuration targeting that port.
It should use the classpath for the local-running:main gradle project.

### Advanced usage

It is also possible to run a subset of services if you wish to run some/all of them yourself
or point them to other local/remote instances.

In some cases you may need to update the configuration in the corresponding `*.env` files,
but care should be taken not to commit any secrets or real configuration values.
