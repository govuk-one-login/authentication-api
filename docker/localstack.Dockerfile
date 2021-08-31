# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.17.3@sha256:0b7cb026facc2c757d933bfb04d2f43e5693ce57204a2fcc42e44ba0cd272307

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
