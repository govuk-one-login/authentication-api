FROM amazoncorretto:17.0.16@sha256:e2adb8e2da6716cf3d8a4090396daa61005d070fe9ea9d9f54de7cfffc942ec0 AS build

WORKDIR /app

RUN yum update -y && yum install -y findutils-4.5.11-6.amzn2 tar-1.26-35.amzn2.0.4 && yum clean all && rm -rf /var/cache/yum

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
COPY account-data-api ./account-data-api
COPY orchestration-shared ./orchestration-shared
COPY client-registry-api ./client-registry-api
COPY deprecation-checker ./deprecation-checker
COPY interventions-api-stub ./interventions-api-stub
COPY account-data-api-integration-tests ./account-data-api-integration-tests
COPY test-services-api ./test-services-api
COPY utils ./utils
COPY identity-shared ./identity-shared
COPY orchestration-shared-test ./orchestration-shared-test
COPY oidc-api ./oidc-api
COPY ipv-api ./ipv-api
COPY account-management-api ./account-management-api
COPY shared-test ./shared-test
COPY delivery-receipts-api ./delivery-receipts-api
COPY ticf-cri-stub ./ticf-cri-stub
COPY sis-api ./sis-api
COPY doc-checking-app-api ./doc-checking-app-api
COPY delivery-receipts-integration-tests ./delivery-receipts-integration-tests
COPY orchestration-local-running ./orchestration-local-running
COPY integration-tests ./integration-tests
COPY account-management-integration-tests ./account-management-integration-tests

RUN --mount=type=cache,target=/root/.gradle ./gradlew :local-running:build --no-daemon
RUN mkdir untarred && tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM amazoncorretto:17.0.16@sha256:e2adb8e2da6716cf3d8a4090396daa61005d070fe9ea9d9f54de7cfffc942ec0

WORKDIR /app

COPY --from=build /app/untarred/local-running .

ENV PORT=4402
EXPOSE $PORT

ENTRYPOINT ["./bin/local-running"]
