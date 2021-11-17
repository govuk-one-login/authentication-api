# localstack Dockerfile
#
# Container used to run tasks requiring Localstack in the build pipeline.

FROM localstack/localstack:0.13.0@sha256:7bfc0f198875d734f158b4a981f4f8d0e218afccb8fd503a173dfb19b1be0d5e

COPY localstack/*.sh /docker-entrypoint-initaws.d/

RUN apt install argon2
