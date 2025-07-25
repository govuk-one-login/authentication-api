FROM amazoncorretto:17 AS build

WORKDIR /app

RUN yum update -y && yum install -y findutils tar

COPY gradle ./gradle
COPY gradlew ./
COPY *.gradle ./

RUN ./gradlew --version

COPY spotbugsExclude.xml ./
COPY local-running ./local-running
COPY shared ./shared
COPY auth-external-api ./auth-external-api
COPY frontend-api ./frontend-api

RUN --mount=type=cache,target=/root/.gradle ./gradlew :local-running:build --no-daemon
RUN mkdir untarred && tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM amazoncorretto:17

WORKDIR /app

COPY --from=build /app/untarred/local-running .

ENV PORT 4402
EXPOSE $PORT

ENTRYPOINT ["./bin/local-running"]
