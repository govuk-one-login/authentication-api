# Local running for Authentication API

This directory contains a wrapper for running the authentication API locally without an AWS environment.

It can be used to test code changes quickly and with a debugger,
but cannot be used to fully test changes involving AWS components.  

## How it works

The local-running app runs a [Javalin](https://javalin.io/) webserver which simulates the API Gateway integration,
transforming incoming requests to lambda handler invocations.

See [LocalAuthApi.java](./src/main/java/uk/gov/di/authentication/local/LocalAuthApi.java) for the mapping.

It runs both `frontend-api` and `external-api` on the same server.

## How to use

### Prerequisites

The `authentication-stubs` and `authentication-frontend` repos will need to be checked out (or symlinked)
at the same level as `authentication-api`, and the containers will be built from the current branch:

```
<dev workspace>
├─ authentication-api/
├─ authentication-frontend/
├─ authentication-stubs/
```

### Basic usage

The simplest way is to run `docker compose up` in the repository root. This will spin up a number of containers:

- `aws` - Localstack instance for SSM, KMS, and SQS dependencies
- `redis` - Redis container for remaining redis dependencies
- `dynamodb` - DynamoDB container for DynamoDB tables
- `orchestrator-stub` - Orchestrator stub for starting auth journeys, running on [http://localhost:4400]
- `authentication-frontend` - Auth frontend running on [http://localhost:4401]
- `authentication-api` - Local running Auth API running on [http://localhost:4402] 

The orchestrator stub will run at [http://localhost:4400] and journeys can be started there.

Standard docker compose commands can be used to rebuild containers when needed,
e.g. `docker compose build authentication-api`. 

### Advanced usage

It is also possible to run a subset of these services if you wish to run some/all of them yourself
or point them to a separate instance.

In some cases you may need to update the configuration in the corresponding `*.env` files,
but care should be taken not to commit any secrets or real configuration values.
