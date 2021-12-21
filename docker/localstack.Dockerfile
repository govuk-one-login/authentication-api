# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.2@sha256:e3a4c6a2a9ba3c34ac4cfeed071785b11919b7a822c1aac3154aa694e2d73854

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
