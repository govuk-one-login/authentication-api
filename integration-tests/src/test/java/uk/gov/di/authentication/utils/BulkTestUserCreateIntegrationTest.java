package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.BulkTestUserS3Extension;
import uk.gov.di.authentication.sharedtest.helper.S3TestEventHelper;
import uk.gov.di.authentication.utils.lambda.BulkTestUserCreateHandler;

import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.extensions.BulkTestUserS3Extension.BULK_TEST_USER_BUCKET;
import static uk.gov.di.authentication.sharedtest.extensions.BulkTestUserS3Extension.TEST_FILE_NAME;

class BulkTestUserCreateIntegrationTest extends HandlerIntegrationTest<S3Event, Void> {

    private static final String REGION =
            Optional.ofNullable(System.getenv().get("AWS_REGION")).orElse("eu-west-2");
    private static final String S3_ENDPOINT =
            Optional.ofNullable(System.getenv().get("LOCALSTACK_ENDPOINT"))
                    .orElse("http://localhost:45678");
    private static final S3Event testS3Event =
            S3TestEventHelper.generateS3TestEvent(
                    REGION, "ObjectCreated:Put", BULK_TEST_USER_BUCKET, TEST_FILE_NAME);

    @RegisterExtension
    protected static final BulkTestUserS3Extension bulkTestUserS3 = new BulkTestUserS3Extension();

    @BeforeEach
    void setup() {
        var mockS3Credentials = AwsBasicCredentials.create("access", "secret");

        var testS3Client =
                S3Client.builder()
                        .endpointOverride(URI.create(S3_ENDPOINT))
                        .region(Region.of(REGION))
                        .credentialsProvider(StaticCredentialsProvider.create(mockS3Credentials))
                        .build();
        handler = new BulkTestUserCreateHandler(TEST_CONFIGURATION_SERVICE, testS3Client);
    }

    @Test
    void movedS3UserProfilesAndCredentialsIntoDynamoWhenTriggered() throws Exception {
        handler.handleRequest(testS3Event, mock(Context.class));
        Map<UserProfile, UserCredentials> testUsers = getTestUsersProfilesAndCredentials();

        List<UserProfile> userStoreAllTestUsers = userStore.getAllTestUsers();
        assertEquals(testUsers.size(), userStoreAllTestUsers.size());
        assertEquals(1, userStoreAllTestUsers.get(0).getTestUser());
    }

    private Map<UserProfile, UserCredentials> getTestUsersProfilesAndCredentials()
            throws Exception {
        var dateTime = LocalDateTime.now().toString();

        URL testFileUrl =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("test_users_integration_test.txt");
        Path testFilePath = Paths.get(testFileUrl.toURI());

        String testFileContent = Files.readString(testFilePath);
        String[] testFileContentAsArray = testFileContent.split("\r?\n|\r");
        List<String> testFileContentAsArrayList =
                new ArrayList<>(Arrays.asList(testFileContentAsArray));
        testFileContentAsArrayList.removeAll(Collections.singleton(null));
        testFileContentAsArrayList.removeAll(Collections.singleton(""));
        testFileContentAsArrayList.removeAll(
                Collections.singleton(
                        "Email,Password,Phone2FA,PhoneNumber,AuthApp2FA,AuthAppSecret"));

        Map<UserProfile, UserCredentials> testUsers = new HashMap<>();
        testFileContentAsArrayList.forEach(
                testUser -> {
                    String[] testUserCsv = testUser.split(",", -1);
                    List<String> testUserCsvAsArrayList =
                            new ArrayList<>(Arrays.asList(testUserCsv));

                    testUsers.put(
                            getUserProfileFromTestUserString(testUserCsvAsArrayList, dateTime),
                            getUserCredentialsFromTestUserString(testUserCsvAsArrayList, dateTime));
                });
        return testUsers;
    }

    private UserProfile getUserProfileFromTestUserString(List<String> testUser, String dateTime) {
        var emailAddress = testUser.get(0);
        boolean isPhoneSecondAuthFactor = testUser.get(2).equals("1");
        var termsAndConditions = new TermsAndConditions("XXX", dateTime);

        var userProfile =
                new UserProfile()
                        .withEmail(emailAddress.toLowerCase(Locale.ROOT))
                        .withSubjectID((new Subject()).toString())
                        .withEmailVerified(true)
                        .withCreated(dateTime)
                        .withUpdated(dateTime)
                        .withPublicSubjectID((new Subject()).toString())
                        .withTermsAndConditions(termsAndConditions)
                        .withLegacySubjectID(null);
        userProfile.setSalt(SaltHelper.generateNewSalt());
        userProfile.setTestUser(1);
        userProfile.setAccountVerified(1);

        if (isPhoneSecondAuthFactor) {
            String phoneNumber = testUser.get(3);
            userProfile.setPhoneNumber(phoneNumber);
            userProfile.setPhoneNumberVerified(true);
        }

        return userProfile;
    }

    private UserCredentials getUserCredentialsFromTestUserString(
            List<String> testUser, String dateTime) {
        var emailAddress = testUser.get(0);
        var plainTextPassword = testUser.get(1);
        boolean isAuthAppSecondAuthFactor = testUser.get(4).equals("1");
        var hashedPassword = hashPassword(plainTextPassword);

        var userCredentials =
                new UserCredentials()
                        .withEmail(emailAddress.toLowerCase(Locale.ROOT))
                        .withSubjectID((new Subject()).toString())
                        .withPassword(hashedPassword)
                        .withCreated(dateTime)
                        .withUpdated(dateTime);
        userCredentials.setTestUser(1);

        if (isAuthAppSecondAuthFactor) {
            String authAppSecret = testUser.get(4);
            List<MFAMethod> mfaMethods = new ArrayList<>();
            var authAppMfaMethod =
                    new MFAMethod(
                            MFAMethodType.AUTH_APP.getValue(), authAppSecret, true, true, dateTime);
            mfaMethods.add(authAppMfaMethod);
            userCredentials.setMfaMethods(mfaMethods);
        }

        return userCredentials;
    }

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }
}
