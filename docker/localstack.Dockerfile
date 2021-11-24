# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.0.4@sha256:0b80edfdef45725ffd084b762dda48fe5edd39e968fe8d1300cdc36acb2595d8

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
