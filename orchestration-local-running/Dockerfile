FROM amazoncorretto:17.0.16@sha256:e2adb8e2da6716cf3d8a4090396daa61005d070fe9ea9d9f54de7cfffc942ec0 AS build

WORKDIR /app

RUN yum update -y && yum install -y findutils-4.5.11-6.amzn2 tar-1.26-35.amzn2.0.4 && yum clean all && rm -rf /var/cache/yum

ADD . .

RUN ./gradlew --version
RUN --mount=type=cache,target=/root/.gradle ./gradlew :orchestration-local-running:build --no-daemon
RUN mkdir untarred && tar -xvf orchestration-local-running/build/distributions/orchestration-local-running.tar -C ./untarred

FROM amazoncorretto:17.0.16@sha256:e2adb8e2da6716cf3d8a4090396daa61005d070fe9ea9d9f54de7cfffc942ec0

WORKDIR /app

COPY --from=build /app/untarred/orchestration-local-running .

ENV PORT=4400
EXPOSE $PORT

ENTRYPOINT ["./bin/orchestration-local-running"]
