# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.1@sha256:3fcef2507cd96b64a5efd94ab25e95fa58b46e97c1217e3c0e3cec352d8376ee

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
