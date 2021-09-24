# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.18@sha256:a1545b6f22b2eef9808a651c633714fc092b568c47021069d5b1a8637a9f8a0e

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
