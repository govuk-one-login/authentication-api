# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.17.4@sha256:a2f37c72c974dccd46140c8832ba0f2f42e67865e7533e28240dc1061c79e8bc

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
