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
└─ authentication-stubs/
```

### Basic usage

The simplest way is to run `docker compose up` in the repository root. This will spin up a number of containers:

- `aws` - Localstack instance for SSM, KMS, and SQS dependencies
- `redis` - Redis container for remaining redis dependencies
- `dynamodb` - DynamoDB container for DynamoDB tables
- `orchestration-stub` - Orchestration stub for starting auth journeys, running on [http://localhost:4400]
- `authentication-frontend` - Auth frontend running on [http://localhost:4401]
- `authentication-api` - Local running Auth API running on [http://localhost:4402]

The orchestrator stub will run at [http://localhost:4400] and journeys can be started there.

Standard docker compose commands can be used to rebuild containers when needed,
e.g. `docker compose build authentication-api`.

### Debugging

#### Authentication API debugging

Authentication API exposes a debug port at `localhost:5402` for use with your favourite Java debugger.

In IntelliJ, you can set up a 'Remote JVM Debug' debug configuration targeting that port.
It should use the classpath for the local-running:main gradle project.

### Authentication Frontend debugging

Authentication Frontend exposes a debug port at `localhost:5401` for use with your favourite Node debugger.

In VSCode, you can set up a `launch.json` configuration to target the port. For example:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "attach",
      "name": "Authentication Frontend",
      "skipFiles": ["<node_internals>/**"],
      "outFiles": ["${workspaceFolder}/dist/**/*.js"],
      "localRoot": "${workspaceFolder}/dist",
      "remoteRoot": "/app/dist",
      "address": "localhost",
      "port": 5401
    }
  ]
}
```

Note that you will need to build the project yourself (`yarn build`) to make the source maps available to the debugger.

### Advanced usage

It is also possible to run a subset of services if you wish to run some/all of them yourself
or point them to other local/remote instances.

In some cases you may need to update the configuration in the corresponding `*.env` files,
but care should be taken not to commit any secrets or real configuration values.
