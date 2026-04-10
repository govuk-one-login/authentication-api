# Authentication API Stub

An [Imposter](https://www.imposter.sh/) stub that replaces the real `authentication-api` backend, allowing the orchestration-stub and authentication-frontend to run without needing the Java API, DynamoDB, Redis, or LocalStack.

## Prerequisites

- Docker
- The following repos cloned as siblings of `authentication-api`:
  ```
  parent-directory/
  ├── authentication-api/          (this repo)
  ├── authentication-frontend/
  └── authentication-stubs/
  ```

## Quick Start

From the repo root:

```shell
docker compose -f stubs/api/imposter/docker-compose.imposter.yml up --build
```

Then open http://localhost:4400 in your browser to start the journey via the orchestration stub.

## Services

| Service                  | Internal Port | Host Port | Description                          |
|--------------------------|---------------|-----------|--------------------------------------|
| orchestration-stub       | 4400          | 4400      | Simulates the orchestration layer    |
| authentication-frontend  | 4401          | 4401      | The real frontend, pointed at the stub |
| api-stub (Imposter)      | 8080          | 4402      | Stub replacing the authentication-api |

## How It Works

The docker-compose starts three containers on a shared network. The orchestration-stub and authentication-frontend are configured (via environment variable overrides) to send API requests to the Imposter stub instead of the real authentication-api.

All stub responses are served from static JSON files in `responses/`. The endpoint mappings are defined in `rest-plugin-config.yaml`.

## Customising Responses

To change what the stub returns for a given endpoint, edit the corresponding JSON file in `responses/`:

```
responses/
├── start-200.json
├── login-200.json
├── signup-200.json
├── user-exists-200.json
├── orch-auth-code-200.json
├── account-interventions-200.json
├── ...
```

Changes to response files are picked up immediately — no restart required, as Imposter serves directly from the mounted volume.

To add a new endpoint, add an entry to `rest-plugin-config.yaml` and create a response file if needed.

## Stopping

```shell
docker compose -f stubs/api/imposter/docker-compose.imposter.yml down
```
