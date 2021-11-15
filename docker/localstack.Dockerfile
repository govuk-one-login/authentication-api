# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.20@sha256:ae2c8cbf90ec8dace5d34ff5690b049f030021a0c1a2f8e49bcb8cd6986fae52

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
