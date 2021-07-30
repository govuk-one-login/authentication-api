# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.15@sha256:9ad944dafff54830ac2c60e07f1f084963ceb3ff71b7dc4ff6d50864affa383d

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
