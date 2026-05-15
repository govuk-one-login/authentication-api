FROM amazoncorretto:25.0.1@sha256:6ba4f6ca82ac3f8bad2e514a1ba060e6314e8dff2d46b06c3bd6af063a7c2eb6 AS build

WORKDIR /app

RUN yum update -y && yum install -y findutils tar

COPY gradle ./gradle
COPY gradlew ./
COPY *.gradle ./

RUN ./gradlew --version

COPY spotbugsExclude.xml ./
COPY orchestration-local-running ./orchestration-local-running
COPY orchestration-shared ./orchestration-shared
COPY oidc-api ./oidc-api
COPY ipv-api ./ipv-api
COPY doc-checking-app-api ./doc-checking-app-api
COPY client-registry-api ./client-registry-api

RUN --mount=type=cache,target=/root/.gradle ./gradlew :orchestration-local-running:build --no-daemon
RUN mkdir untarred && tar -xvf orchestration-local-running/build/distributions/orchestration-local-running.tar -C ./untarred

FROM amazoncorretto:25.0.1@sha256:6ba4f6ca82ac3f8bad2e514a1ba060e6314e8dff2d46b06c3bd6af063a7c2eb6

WORKDIR /app

COPY --from=build /app/untarred/orchestration-local-running .

ENV PORT=4400
EXPOSE $PORT

ENTRYPOINT ["./bin/orchestration-local-running"]
