# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.0.8@sha256:d0ca991b7652c3fcb4078738bd7dbb519a8c7744ea924b038a3b3d02485a14d8

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
