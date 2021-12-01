# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.0.10@sha256:ded18627002d37b9514817ec266e9e0c019378b56c5a6c2d8620e8ee029be690

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
