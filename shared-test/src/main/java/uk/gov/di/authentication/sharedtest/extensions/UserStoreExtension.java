package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndex;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.Projection;
import com.amazonaws.services.dynamodbv2.model.ResourceNotFoundException;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.amazonaws.services.dynamodbv2.model.KeyType.HASH;
import static com.amazonaws.services.dynamodbv2.model.ProjectionType.ALL;
import static com.amazonaws.services.dynamodbv2.model.ScalarAttributeType.S;

public class UserStoreExtension implements BeforeAllCallback, AfterEachCallback {

    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String ENVIRONMENT = System.getenv().getOrDefault("ENVIRONMENT", "local");
    private static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");
    private final DynamoService dynamoService =
            new DynamoService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT));

    private AmazonDynamoDB dynamoDB;

    public boolean userExists(String email) {
        return dynamoService.userExists(email);
    }

    public void signUp(String email, String password) {
        signUp(email, password, new Subject());
    }

    public String signUp(String email, String password, Subject subject) {
        TermsAndConditions termsAndConditions =
                new TermsAndConditions("1.0", LocalDateTime.now(ZoneId.of("UTC")).toString());
        dynamoService.signUp(email, password, subject, termsAndConditions);
        return dynamoService.getUserProfileByEmail(email).getPublicSubjectID();
    }

    public void updateConsent(String email, ClientConsent clientConsent) {
        dynamoService.updateConsent(email, clientConsent);
    }

    public void addPhoneNumber(String email, String phoneNumber) {
        dynamoService.updatePhoneNumber(email, phoneNumber);
        dynamoService.updatePhoneNumberVerifiedStatus(email, true);
    }

    public void setPhoneNumberVerified(String email, boolean isVerified) {
        dynamoService.updatePhoneNumberVerifiedStatus(email, isVerified);
    }

    public Optional<List<ClientConsent>> getUserConsents(String email) {
        return dynamoService.getUserConsents(email);
    }

    public void updateTermsAndConditions(String email, String version) {
        dynamoService.updateTermsAndConditions(email, version);
    }

    public void flushData() {
        clearDynamoTable(dynamoDB, "local-user-credentials", "Email");
        clearDynamoTable(dynamoDB, "local-user-profile", "Email");
    }

    private void clearDynamoTable(AmazonDynamoDB dynamoDB, String tableName, String key) {
        ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
        ScanResult result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.getItems()) {
            dynamoDB.deleteItem(tableName, Map.of(key, item.get(key)));
        }
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        flushData();
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        dynamoDB =
                AmazonDynamoDBClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(DYNAMO_ENDPOINT, REGION))
                        .build();

        if (!tableExists("local-user-profile")) {
            createUserProfileTable("local-user-profile");
        }

        if (!tableExists("local-user-credentials")) {
            createUserCredentialsTable("local-user-credentials");
        }
    }

    private void createUserCredentialsTable(String tableName) {
        CreateTableRequest request =
                new CreateTableRequest()
                        .withTableName(tableName)
                        .withKeySchema(new KeySchemaElement("Email", HASH))
                        .withAttributeDefinitions(
                                new AttributeDefinition("Email", S),
                                new AttributeDefinition("SubjectID", S))
                        .withGlobalSecondaryIndexes(
                                new GlobalSecondaryIndex()
                                        .withIndexName("SubjectIDIndex")
                                        .withKeySchema(new KeySchemaElement("SubjectID", HASH))
                                        .withProjection(new Projection().withProjectionType(ALL)));
        dynamoDB.createTable(request);
    }

    private void createUserProfileTable(String tableName) {
        CreateTableRequest request =
                new CreateTableRequest()
                        .withTableName(tableName)
                        .withKeySchema(new KeySchemaElement("Email", HASH))
                        .withAttributeDefinitions(
                                new AttributeDefinition("Email", S),
                                new AttributeDefinition("SubjectID", S),
                                new AttributeDefinition("PublicSubjectID", S))
                        .withGlobalSecondaryIndexes(
                                new GlobalSecondaryIndex()
                                        .withIndexName("SubjectIDIndex")
                                        .withKeySchema(new KeySchemaElement("SubjectID", HASH))
                                        .withProjection(new Projection().withProjectionType(ALL)),
                                new GlobalSecondaryIndex()
                                        .withIndexName("PublicSubjectIDIndex")
                                        .withKeySchema(
                                                new KeySchemaElement("PublicSubjectID", HASH))
                                        .withProjection(new Projection().withProjectionType(ALL)));
        dynamoDB.createTable(request);
    }

    private boolean tableExists(String tableName) {
        try {
            dynamoDB.describeTable(tableName);
            return true;
        } catch (ResourceNotFoundException ignored) {
            return false;
        }
    }
}
