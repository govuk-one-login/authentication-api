package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.TermsAndConditions;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.time.LocalDateTime;
import java.time.ZoneId;

public class UserStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String USER_CREDENTIALS_TABLE = "local-user-credentials";
    public static final String USER_PROFILE_TABLE = "local-user-profile";
    public static final String EMAIL_FIELD = "Email";
    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String PUBLIC_SUBJECT_ID_FIELD = "PublicSubjectID";

    public static final String ACCOUNT_VERIFIED_FIELD = "accountVerified";
    public static final String TEST_USER_FIELD = "testUser";
    public static final String SUBJECT_ID_INDEX = "SubjectIDIndex";
    public static final String PUBLIC_SUBJECT_ID_INDEX = "PublicSubjectIDIndex";

    public static final String VERIFIED_ACCOUNT_ID_INDEX = "VerifiedAccountIndex";
    public static final String TEST_USER_INDEX = "TestUserIndex";

    private DynamoService dynamoService;

    public void signUp(String email, String password) {
        signUp(email, password, new Subject());
    }

    public String signUp(String email, String password, Subject subject) {
        TermsAndConditions termsAndConditions =
                new TermsAndConditions("1.0", LocalDateTime.now(ZoneId.of("UTC")).toString());
        dynamoService.signUp(email, password, subject, termsAndConditions, false, 1);
        return dynamoService.getUserProfileByEmail(email).getPublicSubjectID();
    }

    public void addVerifiedPhoneNumber(String email, String phoneNumber) {
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(email, phoneNumber, true, true);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        dynamoService =
                new DynamoService(
                        new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT));
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, USER_CREDENTIALS_TABLE, EMAIL_FIELD);
        clearDynamoTable(dynamoDB, USER_PROFILE_TABLE, EMAIL_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(USER_PROFILE_TABLE)) {
            createUserProfileTable(USER_PROFILE_TABLE);
        }

        if (!tableExists(USER_CREDENTIALS_TABLE)) {
            createUserCredentialsTable(USER_CREDENTIALS_TABLE);
        }
    }

    private void createUserCredentialsTable(String tableName) {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(tableName)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(EMAIL_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(EMAIL_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(TEST_USER_FIELD)
                                        .attributeType(ScalarAttributeType.N)
                                        .build())
                        .globalSecondaryIndexes(
                                GlobalSecondaryIndex.builder()
                                        .indexName(SUBJECT_ID_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(SUBJECT_ID_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.ALL))
                                        .build(),
                                GlobalSecondaryIndex.builder()
                                        .indexName(TEST_USER_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(SUBJECT_ID_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(TEST_USER_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.ALL))
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    private void createUserProfileTable(String tableName) {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(tableName)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(EMAIL_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(EMAIL_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(ACCOUNT_VERIFIED_FIELD)
                                        .attributeType(ScalarAttributeType.N)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(TEST_USER_FIELD)
                                        .attributeType(ScalarAttributeType.N)
                                        .build())
                        .globalSecondaryIndexes(
                                GlobalSecondaryIndex.builder()
                                        .indexName(SUBJECT_ID_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(SUBJECT_ID_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.ALL))
                                        .build(),
                                GlobalSecondaryIndex.builder()
                                        .indexName(PUBLIC_SUBJECT_ID_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.ALL))
                                        .build(),
                                GlobalSecondaryIndex.builder()
                                        .indexName(VERIFIED_ACCOUNT_ID_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(SUBJECT_ID_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(ACCOUNT_VERIFIED_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.KEYS_ONLY))
                                        .build(),
                                GlobalSecondaryIndex.builder()
                                        .indexName(TEST_USER_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(SUBJECT_ID_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(TEST_USER_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.KEYS_ONLY))
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
