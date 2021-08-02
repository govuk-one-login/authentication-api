# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.16@sha256:22e869ce3ef9782ea05fd0cc1ea47ed713a205c5e8a9f7d319afcd9bbadedae0

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
