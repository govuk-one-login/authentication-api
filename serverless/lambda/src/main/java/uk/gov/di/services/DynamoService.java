package uk.gov.di.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBQueryExpression;
import com.amazonaws.services.dynamodbv2.datamodeling.QueryResultPage;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.util.Base64;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.entity.ClientConsent;
import uk.gov.di.entity.TermsAndConditions;
import uk.gov.di.entity.UserCredentials;
import uk.gov.di.entity.UserProfile;
import uk.gov.di.helpers.Argon2Helper;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;

public class DynamoService implements AuthenticationService {

    private final DynamoDBMapper userCredentialsMapper;
    private final DynamoDBMapper userProfileMapper;
    private static final String USER_CREDENTIALS_TABLE = "user-credentials";
    private static final String USER_PROFILE_TABLE = "user-profile";

    public DynamoService(String region, String environment, Optional<String> dynamoEndpoint) {
        AmazonDynamoDB dynamoDB =
                dynamoEndpoint
                        .map(
                                t ->
                                        AmazonDynamoDBClientBuilder.standard()
                                                .withEndpointConfiguration(
                                                        new AwsClientBuilder.EndpointConfiguration(
                                                                t, region)))
                        .orElse(AmazonDynamoDBClientBuilder.standard().withRegion(region))
                        .build();

        DynamoDBMapperConfig userCredentialsConfig =
                new DynamoDBMapperConfig.Builder()
                        .withTableNameOverride(
                                DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(
                                        environment + "-" + USER_CREDENTIALS_TABLE))
                        .build();
        DynamoDBMapperConfig userProfileConfig =
                new DynamoDBMapperConfig.Builder()
                        .withTableNameOverride(
                                DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(
                                        environment + "-" + USER_PROFILE_TABLE))
                        .build();
        this.userCredentialsMapper = new DynamoDBMapper(dynamoDB, userCredentialsConfig);
        this.userProfileMapper = new DynamoDBMapper(dynamoDB, userProfileConfig);
        this.userProfileMapper.load(UserProfile.class, "TestKey1");
        this.userProfileMapper.load(UserProfile.class, "TestKey1");
    }

    @Override
    public boolean userExists(String email) {
        return userProfileMapper.load(UserProfile.class, email) != null;
    }

    @Override
    public void signUp(String email, String password, Subject subject) {
        String dateTime = LocalDateTime.now().toString();
        String hashedPassword = hashPassword(password);
        UserCredentials userCredentials =
                new UserCredentials()
                        .setEmail(email)
                        .setSubjectID(subject.toString())
                        .setPassword(hashedPassword)
                        .setCreated(dateTime)
                        .setUpdated(dateTime);
        UserProfile userProfile =
                new UserProfile()
                        .setEmail(email)
                        .setSubjectID(subject.toString())
                        .setEmailVerified(true)
                        .setCreated(dateTime)
                        .setUpdated(dateTime);
        userCredentialsMapper.save(userCredentials);
        userProfileMapper.save(userProfile);
    }

    @Override
    public boolean login(String email, String password) {
        UserCredentials userCredentials = userCredentialsMapper.load(UserCredentials.class, email);
        return verifyPassword(userCredentials.getPassword(), password);
    }

    @Override
    public boolean isEmailVerificationRequired() {
        return false;
    }

    @Override
    public Subject getSubjectFromEmail(String email) {
        return new Subject(userProfileMapper.load(UserProfile.class, email).getSubjectID());
    }

    @Override
    public void updatePhoneNumber(String email, String phoneNumber) {
        userProfileMapper.save(
                userProfileMapper.load(UserProfile.class, email).setPhoneNumber(phoneNumber));
    }

    @Override
    public void updateConsent(String email, ClientConsent clientConsent) {
        userProfileMapper.save(
                userProfileMapper.load(UserProfile.class, email).setClientConsent(clientConsent));
    }

    @Override
    public void updateTermsAndConditions(String email, String version) {
        String epochTime = String.valueOf(Instant.now().getEpochSecond());
        TermsAndConditions termsAndConditions = new TermsAndConditions(version, epochTime);

        userProfileMapper.save(
                userProfileMapper
                        .load(UserProfile.class, email)
                        .setTermsAndConditions(termsAndConditions));
    }

    @Override
    public Optional<List<ClientConsent>> getUserConsents(String email) {
        return Optional.ofNullable(
                userProfileMapper.load(UserProfile.class, email).getClientConsent());
    }

    @Override
    public void updatePhoneNumberVerifiedStatus(String email, boolean verifiedStatus) {
        userProfileMapper.save(
                userProfileMapper
                        .load(UserProfile.class, email)
                        .setPhoneNumberVerified(verifiedStatus));
    }

    @Override
    public Optional<String> getPhoneNumber(String email) {
        return Optional.ofNullable(
                userProfileMapper.load(UserProfile.class, email).getPhoneNumber());
    }

    @Override
    public UserProfile getUserProfileFromSubject(String subject) {
        Map<String, AttributeValue> eav = new HashMap<>();
        eav.put(":val1", new AttributeValue().withS(subject));

        DynamoDBQueryExpression<UserProfile> queryExpression =
                new DynamoDBQueryExpression<UserProfile>()
                        .withIndexName("SubjectIDIndex")
                        .withKeyConditionExpression("SubjectID= :val1")
                        .withExpressionAttributeValues(eav)
                        .withConsistentRead(false);

        QueryResultPage<UserProfile> scanPage =
                userProfileMapper.queryPage(UserProfile.class, queryExpression);
        if (scanPage.getResults().isEmpty() || scanPage.getResults().size() > 1) {
            throw new RuntimeException(
                    format(
                            "Invalid number of query expressions returned: %s",
                            scanPage.getResults().size()));
        }
        return scanPage.getResults().get(0);
    }

    private static String hashPassword(String password) {
        return Base64.encodeAsString(Argon2Helper.argon2Hash(password.getBytes()));
    }

    private static boolean verifyPassword(String hashedPassword, String password) {
        return hashedPassword.equals(hashPassword(password));
    }
}
