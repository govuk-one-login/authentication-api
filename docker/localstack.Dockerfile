# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.17.5@sha256:0036c34d168d88c41a852d6c8e4cf2a8c0c7abf43257d0748b85d7399f9d5dde

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
