# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.19.1@sha256:da8e29a6121dc6436c4fec24c4ebd0694a328b70ce4739d9fdc9b2365e73d8fb

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
