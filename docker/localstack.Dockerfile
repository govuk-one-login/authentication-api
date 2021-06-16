# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.12.11@sha256:a403cab0daa5ccfe8f9af6067f8165e9c82a0e626211b8442163300921e7e0cb

COPY localstack/*.sh /docker-entrypoint-initaws.d/
