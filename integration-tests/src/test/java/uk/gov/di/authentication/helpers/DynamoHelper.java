package uk.gov.di.authentication.helpers;

import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.DynamoService;

import java.util.List;
import java.util.Optional;

public class DynamoHelper {
    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String ENVIRONMENT = System.getenv().getOrDefault("ENVIRONMENT", "local");
    private static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");

    private static final DynamoService DYNAMO_SERVICE =
            new DynamoService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT));

    private static final DynamoClientService DYNAMO_CLIENT_SERVICE =
            new DynamoClientService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT));

    public static boolean userExists(String email) {
        return DYNAMO_SERVICE.userExists(email);
    }

    public static void signUp(String email, String password) {
        DYNAMO_SERVICE.signUp(email, password);
    }

    public static void addPhoneNumber(String email, String phoneNumber) {
        DYNAMO_SERVICE.updatePhoneNumber(email, phoneNumber);
    }

    public static void registerClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey,
            List<String> postLogoutRedirectUris) {
        DYNAMO_CLIENT_SERVICE.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                scopes,
                publicKey,
                postLogoutRedirectUris);
    }

    public static boolean clientExists(String clientID) {
        return DYNAMO_CLIENT_SERVICE.isValidClient(clientID);
    }
}
