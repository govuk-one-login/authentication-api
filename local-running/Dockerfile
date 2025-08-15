FROM amazoncorretto:17.0.16@sha256:e2adb8e2da6716cf3d8a4090396daa61005d070fe9ea9d9f54de7cfffc942ec0 AS build

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

FROM amazoncorretto:17.0.16@sha256:e2adb8e2da6716cf3d8a4090396daa61005d070fe9ea9d9f54de7cfffc942ec0

WORKDIR /app

COPY --from=build /app/untarred/local-running .

ENV PORT=4402
EXPOSE $PORT

ENTRYPOINT ["./bin/local-running"]
