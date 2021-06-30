package uk.gov.di.authentication.helpers;

import uk.gov.di.services.DynamoService;

import java.util.Optional;

public class DynamoHelper {
    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String ENVIRONMENT = System.getenv().getOrDefault("ENVIRONMENT", "local");
    private static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");

    private static final DynamoService DYNAMO_SERVICE =
            new DynamoService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT));

    public static boolean userExists(String email) {
        return DYNAMO_SERVICE.userExists(email);
    }
}
