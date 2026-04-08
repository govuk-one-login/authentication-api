package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

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

    public boolean userExists(String email) {
        return dynamoService.userExists(email);
    }

    public String getEmailForUser(Subject subject) {
        var credentials = dynamoService.getUserCredentialsFromSubject(subject.getValue());
        return credentials.getEmail();
    }

    public String getPasswordForUser(String email) {
        var credentials = dynamoService.getUserCredentialsFromEmail(email);
        return credentials.getPassword();
    }

    public String getPublicSubjectIdForEmail(String email) {
        return dynamoService
                .getUserProfileByEmailMaybe(email)
                .map(UserProfile::getPublicSubjectID)
                .orElseThrow();
    }

    public Optional<String> getPhoneNumberForUser(String email) {
        return dynamoService.getPhoneNumber(email);
    }

    public String signUp(String email, String password) {
        return signUp(email, password, new Subject());
    }

    public String signUp(String email, String password, Subject subject) {
        return signUp(email, password, subject, false);
    }

    public String addUnverifiedUser(
            String email, String password, Subject subject, String termsAndConditionsVersion) {
        return signUp(
                email, password, subject, false, Optional.ofNullable(termsAndConditionsVersion), 0);
    }

    public String addUnverifiedUser(String email, String password) {
        return signUp(email, password, new Subject(), false, Optional.of("1.0"), 0);
    }

    public String signUp(
            String email, String password, Subject subject, String termsAndConditionsVersion) {
        return signUp(
                email, password, subject, false, Optional.ofNullable(termsAndConditionsVersion), 1);
    }

    public String signUp(String email, String password, Subject subject, boolean isTestUser) {
        return signUp(email, password, subject, isTestUser, Optional.of("1.0"), 1);
    }

    public String signUpWithCreationDate(
            String email, String password, Subject subject, String creationDate) {
        String publicSubjectId = signUp(email, password, subject);
        setUserCreationDate(email, creationDate);
        return publicSubjectId;
    }

    public void setUserCreationDate(String email, String creationDate) {
        var userProfileTableName =
                TableNameHelper.getFullTableName(
                        "user-profile", ConfigurationService.getInstance());
        var dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(ConfigurationService.getInstance());
        var dynamoUserProfileTable =
                dynamoDbEnhancedClient.table(
                        userProfileTableName, TableSchema.fromBean(UserProfile.class));

        UserProfile userProfile =
                dynamoUserProfileTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        if (userProfile != null) {
            userProfile.setCreated(creationDate);
            dynamoUserProfileTable.updateItem(userProfile);
        }
    }

    private String signUp(
            String email,
            String password,
            Subject subject,
            boolean isTestUser,
            Optional<String> termsAndConditionsVersion,
            int accountVerified) {
        TermsAndConditions termsAndConditions =
                termsAndConditionsVersion
                        .map(
                                v ->
                                        new TermsAndConditions(
                                                v, LocalDateTime.now(ZoneId.of("UTC")).toString()))
                        .orElse(null);
        dynamoService.signUp(
                email, password, subject, termsAndConditions, isTestUser, accountVerified);
        return dynamoService.getUserProfileByEmail(email).getPublicSubjectID();
    }

    public void createBulkTestUsers(Map<UserProfile, UserCredentials> testUsers) {
        dynamoService.createBatchTestUsers(testUsers);
    }

    public void deleteUserCredentials(String email) {
        var userCredentialsTableName =
                TableNameHelper.getFullTableName(
                        "user-credentials", ConfigurationService.getInstance());
        var dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(ConfigurationService.getInstance());
        var dynamoUserCredentialsTable =
                dynamoDbEnhancedClient.table(
                        userCredentialsTableName, TableSchema.fromBean(UserCredentials.class));
        var key = Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build();
        dynamoUserCredentialsTable.deleteItem(key);
    }

    public void deleteUserProfile(String email) {
        var userProfileTableName =
                TableNameHelper.getFullTableName(
                        "user-profile", ConfigurationService.getInstance());
        var dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(ConfigurationService.getInstance());
        var dynamoUserProfileTable =
                dynamoDbEnhancedClient.table(
                        userProfileTableName, TableSchema.fromBean(UserCredentials.class));
        var key = Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build();
        dynamoUserProfileTable.deleteItem(key);
    }

    public List<UserProfile> getAllTestUsers() {
        return dynamoService.getAllBulkTestUsers();
    }

    public Optional<UserProfile> getUserProfileFromEmail(String email) {
        return dynamoService.getUserProfileFromEmail(email);
    }

    public Optional<UserCredentials> getUserCredentialsFromEmail(String email) {
        return Optional.of(dynamoService.getUserCredentialsFromEmail(email));
    }

    public void addVerifiedPhoneNumber(String email, String phoneNumber) {
        setPhoneNumberAndVerificationStatus(email, phoneNumber, true, true);
    }

    public void addUnverifiedPhoneNumber(String email, String phoneNumber) {
        setPhoneNumberAndVerificationStatus(email, phoneNumber, false, true);
    }

    public void setPhoneNumberMfaIdentifer(String email, String mfaIdentifier) {
        dynamoService.setMfaIdentifierForNonMigratedSmsMethod(email, mfaIdentifier);
    }

    public void setPhoneNumberAndVerificationStatus(
            String email,
            String phoneNumber,
            boolean phoneNumberVerified,
            boolean accountVerified) {
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                email, phoneNumber, phoneNumberVerified, accountVerified);
    }

    public void setAccountVerified(String email) {
        dynamoService.setAccountVerified(email);
    }

    public void setMfaMethodsMigrated(String email, boolean mfaMethodsMigrated) {
        dynamoService.setMfaMethodsMigrated(email, mfaMethodsMigrated);
    }

    public List<MFAMethod> getMfaMethod(String email) {
        return dynamoService.getUserCredentialsFromEmail(email).getMfaMethods();
    }

    public byte[] addSalt(String email) {
        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(email).orElseThrow();

        return dynamoService.getOrGenerateSalt(userProfile);
    }

    public void updateTermsAndConditions(String email, String version) {
        dynamoService.updateTermsAndConditions(email, version);
    }

    public boolean isAccountVerified(String email) {
        return dynamoService.getUserProfileByEmail(email).getAccountVerified() == 1;
    }

    public boolean isPhoneNumberVerified(String email) {
        return dynamoService.getUserProfileByEmail(email).isPhoneNumberVerified();
    }

    public boolean isAuthAppVerified(String email) {
        return Optional.ofNullable(dynamoService.getUserCredentialsFromEmail(email).getMfaMethods())
                .map(
                        t ->
                                t.stream()
                                        .filter(
                                                e ->
                                                        e.getMfaMethodType()
                                                                .equals(
                                                                        MFAMethodType.AUTH_APP
                                                                                .getValue()))
                                        .anyMatch(MFAMethod::isMethodVerified))
                .orElse(false);
    }

    public boolean isAuthAppEnabled(String email) {
        var mfaMethods = dynamoService.getUserCredentialsFromEmail(email).getMfaMethods();
        return mfaMethods != null
                && mfaMethods.stream()
                        .filter(t -> t.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue()))
                        .anyMatch(MFAMethod::isEnabled);
    }

    public void addAuthAppMethod(
            String email, boolean isVerified, boolean isEnabled, String credentialValue) {
        dynamoService.updateMFAMethod(
                email, MFAMethodType.AUTH_APP, isVerified, isEnabled, credentialValue);
    }

    public void addAuthAppMethodWithIdentifier(
            String email,
            boolean isVerified,
            boolean isEnabled,
            String credentialValue,
            String identifier) {
        dynamoService.updateMFAMethod(
                email, MFAMethodType.AUTH_APP, isVerified, isEnabled, credentialValue);
        dynamoService.setMfaIdentifierForNonMigratedUserEnabledAuthApp(email, identifier);
    }

    public void addMfaMethod(
            String email,
            MFAMethodType mfaMethodType,
            boolean isVerified,
            boolean isEnabled,
            String credentialValue) {
        dynamoService.updateMFAMethod(email, mfaMethodType, isVerified, isEnabled, credentialValue);
    }

    public void addMfaMethodSupportingMultiple(String email, MFAMethod mfaMethod) {
        dynamoService.addMFAMethodSupportingMultiple(email, mfaMethod);
    }

    public void updateMFAMethod(
            String email,
            MFAMethodType mfaMethodType,
            boolean methodVerified,
            boolean enabled,
            String credentialValue) {
        dynamoService.updateMFAMethod(
                email, mfaMethodType, methodVerified, enabled, credentialValue);
    }

    public void clearUserCredentialsTable() {
        clearDynamoTable(dynamoDB, USER_CREDENTIALS_TABLE, EMAIL_FIELD);
    }

    public void clearUserProfileTable() {
        clearDynamoTable(dynamoDB, USER_PROFILE_TABLE, EMAIL_FIELD);
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
        clearUserCredentialsTable();
        clearUserProfileTable();
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
