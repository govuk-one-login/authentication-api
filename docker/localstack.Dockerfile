# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.3@sha256:d77700d17e7f19b429c6b6f9963f48fe0ddc5e89b85b6e4d7868ecb75d81e67e

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
