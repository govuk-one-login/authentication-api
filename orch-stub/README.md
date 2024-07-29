# Orchestration Stub

## Running Locally

```bash
sam build && docker compose up --detach && sam local start-api --docker-network lambda-local --parameter-overrides 'Environment=local'
```

Live reload

```bash
sam build
```

Redis passwords containing special characters should be URL encoded
