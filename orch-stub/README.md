# Orchestration Stub

## Running Locally

```bash
sam build && docker compose up --detach && sam local start-api --docker-network lambda-local -n local.env.json  --parameter-overrides 'Environment=local'
```

Live reload

```bash
sam build
```
