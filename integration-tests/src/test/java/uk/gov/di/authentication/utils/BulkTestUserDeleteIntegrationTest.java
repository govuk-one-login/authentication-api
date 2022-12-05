package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.utils.lambda.BulkTestUserDeleteHandler;

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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class BulkTestUserDeleteIntegrationTest extends HandlerIntegrationTest<String, Void> {
    private static final Logger LOG = LogManager.getLogger(BulkTestUserDeleteIntegrationTest.class);

    @BeforeEach
    void setup() throws Exception {
        setUpDynamoWithTestUsers();
        handler = new BulkTestUserDeleteHandler(TEST_CONFIGURATION_SERVICE);
    }

    private void setUpDynamoWithTestUsers() throws Exception {
        long startTime = System.nanoTime();
        Map<UserProfile, UserCredentials> bulkTestUsersToWriteToDb =
                getTestUsersProfilesAndCredentials();
        userStore.createBulkTestUsers(bulkTestUsersToWriteToDb);
        long endTime = System.nanoTime();
        long durationInMilliseconds = (endTime - startTime) / 1000000;
        LOG.info(
                "Integration test bulk user insert operation took {} ms for {} records",
                durationInMilliseconds,
                bulkTestUsersToWriteToDb.size());
    }

    @Test
    void allTestUsersAreDeleted() throws Exception {
        Map<UserProfile, UserCredentials> testUsers = getTestUsersProfilesAndCredentials();

        assertTrue(
                userStore.userExists(
                        testUsers.entrySet().stream().iterator().next().getKey().getEmail()));

        handler.handleRequest(mock(String.class), mock(Context.class));

        testUsers.forEach((key, value) -> assertFalse(userStore.userExists(key.getEmail())));
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
