# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.17@sha256:a7b43e050e5621277fd37ae09277c460810256ec1d71a9b519b3684a05259e20

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apk add argon2 argon2-dev
