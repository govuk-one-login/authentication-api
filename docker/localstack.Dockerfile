# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.0@sha256:b42729350cc110dfc896462c90cc2d4ce37ccf119ee51fd0cc08f729c304236d

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
