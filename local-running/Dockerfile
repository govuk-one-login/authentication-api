FROM amazoncorretto:25.0.1@sha256:6ba4f6ca82ac3f8bad2e514a1ba060e6314e8dff2d46b06c3bd6af063a7c2eb6 AS build

WORKDIR /app

RUN yum update -y && yum install -y findutils tar

COPY gradle ./gradle
COPY gradlew ./
COPY *.gradle ./

RUN ./gradlew --version

COPY spotbugsExclude.xml ./
COPY local-running ./local-running
COPY shared ./shared
COPY user-permissions ./user-permissions
COPY auth-external-api ./auth-external-api
COPY frontend-api ./frontend-api
COPY audit-events ./audit-events

RUN --mount=type=cache,target=/root/.gradle ./gradlew :local-running:build --no-daemon
RUN mkdir untarred && tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM amazoncorretto:25.0.1@sha256:6ba4f6ca82ac3f8bad2e514a1ba060e6314e8dff2d46b06c3bd6af063a7c2eb6

WORKDIR /app

COPY --from=build /app/untarred/local-running .

ENV PORT=4402
EXPOSE $PORT

ENTRYPOINT ["./bin/local-running"]
