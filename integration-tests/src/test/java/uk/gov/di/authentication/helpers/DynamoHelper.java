package uk.gov.di.authentication.helpers;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.time.Instant;
import java.util.List;
import java.util.Map;
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

    public static UserProfile getUserProfileByEmail(String email) {
        return DYNAMO_SERVICE.getUserProfileByEmail(email);
    }

    public static void signUp(String email, String password) {
        signUp(email, password, new Subject());
    }

    public static Subject getSubjectFromEmail(String email) {
        return DYNAMO_SERVICE.getSubjectFromEmail(email);
    }

    public static void signUp(String email, String password, Subject subject) {
        TermsAndConditions termsAndConditions =
                new TermsAndConditions("1.0", String.valueOf(Instant.now().getEpochSecond()));
        DYNAMO_SERVICE.signUp(email, password, subject, termsAndConditions);
    }

    public static void updateConsent(String email, ClientConsent clientConsent) {
        DYNAMO_SERVICE.updateConsent(email, clientConsent);
    }

    public static UserProfile getByPublicSubject(String subject) {
        return DYNAMO_SERVICE.getUserProfileFromPublicSubject(subject);
    }

    public static void addPhoneNumber(String email, String phoneNumber) {
        DYNAMO_SERVICE.updatePhoneNumber(email, phoneNumber);
        DYNAMO_SERVICE.updatePhoneNumberVerifiedStatus(email, true);
    }

    public static void setPhoneNumberVerified(String email, boolean isVerified) {
        DYNAMO_SERVICE.updatePhoneNumberVerifiedStatus(email, isVerified);
    }

    public static Optional<List<ClientConsent>> getUserConsents(String email) {
        return DYNAMO_SERVICE.getUserConsents(email);
    }

    public static void updateTermsAndConditions(String email, String version) {
        DYNAMO_SERVICE.updateTermsAndConditions(email, version);
    }

    public static void registerClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey,
            List<String> postLogoutRedirectUris,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            String vectorsOfTrust) {
        DYNAMO_CLIENT_SERVICE.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                scopes,
                publicKey,
                postLogoutRedirectUris,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                vectorsOfTrust);
    }

    public static boolean clientExists(String clientID) {
        return DYNAMO_CLIENT_SERVICE.isValidClient(clientID);
    }

    public static void flushData() {
        AmazonDynamoDB dynamoDB =
                AmazonDynamoDBClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(DYNAMO_ENDPOINT, REGION))
                        .build();

        clearDynamoTable(dynamoDB, "local-user-credentials", "Email");
        clearDynamoTable(dynamoDB, "local-user-profile", "Email");
        clearDynamoTable(dynamoDB, "local-client-registry", "ClientID");
    }

    private static void clearDynamoTable(AmazonDynamoDB dynamoDB, String tableName, String key) {
        ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
        ScanResult result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.getItems()) {
            dynamoDB.deleteItem(tableName, Map.of(key, item.get(key)));
        }
    }
}
