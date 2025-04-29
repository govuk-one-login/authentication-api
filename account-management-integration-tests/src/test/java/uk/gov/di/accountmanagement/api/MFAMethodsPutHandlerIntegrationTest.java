package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.MFAMethodsPutHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsPutHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static String testInternalSubject;

    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "+447700900000";
    private static final String TEST_PHONE_NUMBER_TWO = "+447700900111";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static String testPublicSubject;
    private static final MFAMethod defaultPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    TEST_PHONE_NUMBER,
                    PriorityIdentifier.DEFAULT,
                    UUID.randomUUID().toString());
    private static final MFAMethod backupPrioritySms =
            MFAMethod.smsMfaMethod(
                    true, true, TEST_PHONE_NUMBER_TWO, BACKUP, UUID.randomUUID().toString());
    private static final MFAMethod defaultPriorityAuthApp =
            MFAMethod.authAppMfaMethod(
                    TEST_CREDENTIAL,
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    UUID.randomUUID().toString());

    @BeforeEach
    void setUp() {
        ConfigurationService mfaMethodEnabledConfigurationService =
                new ConfigurationService() {
                    @Override
                    public boolean isMfaMethodManagementApiEnabled() {
                        return true;
                    }
                };

        handler = new MFAMethodsPutHandler(mfaMethodEnabledConfigurationService);
        testPublicSubject = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        testInternalSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userStore.getUserProfileFromEmail(TEST_EMAIL).get().getSubjectID(),
                        INTERNAL_SECTOR_HOST,
                        salt);
    }

    @Test
    void shouldReturn200AndMfaMethodDataWhenAuthAppUserUpdatesTheirCredential() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
        var mfaIdentifier = defaultPriorityAuthApp.getMfaIdentifier();
        var updatedCredential = "some-new-credential";
        var updateRequest =
                format(
                        """
                                {
                                  "mfaMethod": {
                                    "priorityIdentifier": "DEFAULT",
                                    "method": {
                                        "mfaMethodType": "AUTH_APP",
                                        "credential": "%s"
                                    }
                                  }
                                }
                                """,
                        updatedCredential);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                mfaIdentifier),
                        Map.of("principalId", testInternalSubject));

        var expectedResponseBody =
                format(
                        """
                                [{
                                    "mfaIdentifier":"%s",
                                    "priorityIdentifier":"DEFAULT",
                                    "methodVerified":true,
                                    "method": {
                                      "mfaMethodType":"AUTH_APP",
                                      "credential":"%s"
                                    }
                                }]
                                """,
                        mfaIdentifier, updatedCredential);
        assertEquals(200, response.getStatusCode());

        var expectedResponse =
                JsonParser.parseString(expectedResponseBody).getAsJsonArray().toString();
        assertEquals(expectedResponse, response.getBody());

        var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        assertEquals(1, retrievedMfaMethods.size());

        var retrievedMethod = retrievedMfaMethods.get(0);

        assertRetrievedMethodHasSameBasicFields(defaultPriorityAuthApp, retrievedMethod);
        assertMfaCredentialUpdated(retrievedMethod, updatedCredential);
    }

    @Test
    void shouldMigrateANonMigratedUserBeforePerformingAnyUpdates() {
        var mfaIdentifier = "mfaIdentifierForNonMigratedSms";
        // Set up a user with sms in the old way, but with an mfa identifier (which they will have
        // via the get request)
        userStore.setPhoneNumberAndVerificationStatus(TEST_EMAIL, TEST_PHONE_NUMBER, true, true);
        userStore.setPhoneNumberMfaIdentifer(TEST_EMAIL, mfaIdentifier);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, false);

        var secondPhoneNumber = "+447900000100";
        var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

        var updateRequest =
                format(
                        """
                                {
                                  "mfaMethod": {
                                    "priorityIdentifier": "DEFAULT",
                                    "method": {
                                        "mfaMethodType": "SMS",
                                        "phoneNumber": "%s",
                                        "otp": "%s"
                                    }
                                  }
                                }
                                """,
                        secondPhoneNumber, otp);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                mfaIdentifier),
                        Map.of("principalId", testInternalSubject));

        var expectedResponseBody =
                format(
                        """
                                [{
                                    "mfaIdentifier":"%s",
                                    "priorityIdentifier":"DEFAULT",
                                    "methodVerified":true,
                                    "method": {
                                      "mfaMethodType":"SMS",
                                      "phoneNumber":"%s"
                                    }
                                }]
                                """,
                        mfaIdentifier, secondPhoneNumber);
        assertEquals(200, response.getStatusCode());

        var expectedResponse =
                JsonParser.parseString(expectedResponseBody).getAsJsonArray().toString();
        assertEquals(expectedResponse, response.getBody());

        var userProfileAfterUpdate = userStore.getUserProfileFromEmail(TEST_EMAIL).get();
        // Assert that all the things we expect to happen during migration have happened - all
        // redundant fields
        // cleared, and methodsMigrated set to true
        assertTrue(userProfileAfterUpdate.getMfaMethodsMigrated());
        assertFalse(userProfileAfterUpdate.isPhoneNumberVerified());
        assertNull(userProfileAfterUpdate.getPhoneNumber());

        // Assert that the updates have been made and the SMS method is now in the user credentials
        // table with
        // all the relevant fields post migration
        var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        assertEquals(1, retrievedMfaMethods.size());

        var retrievedMethod = retrievedMfaMethods.get(0);

        assertEquals(MFAMethodType.SMS.getValue(), retrievedMethod.getMfaMethodType());
        assertEquals(DEFAULT.name(), retrievedMethod.getPriority());
        assertEquals(mfaIdentifier, retrievedMethod.getMfaIdentifier());
        assertTrue(retrievedMethod.isEnabled());
        assertTrue(retrievedMethod.isMethodVerified());
        assertEquals(secondPhoneNumber, retrievedMethod.getDestination());
    }

    @Test
    void
            shouldReturn200AndSwitchMfaMethodPrioritiesWhenAUserSwitchesTheirBackupMethodWithTheirDefault() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var backupMfaIdentifier = backupPrioritySms.getMfaIdentifier();
        var updateRequest =
                        """
                                {
                                  "mfaMethod": {
                                    "priorityIdentifier": "DEFAULT"
                                  }
                                }
                                """;

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                backupMfaIdentifier),
                        Map.of("principalId", testInternalSubject));

        var expectedPromotedBackup =
                format(
                        """
                        {
                             "mfaIdentifier":"%s",
                             "priorityIdentifier":"DEFAULT",
                             "methodVerified":true,
                             "method": {
                               "mfaMethodType":"SMS",
                               "phoneNumber":"%s"
                             }
                         }
                        """,
                        backupMfaIdentifier, backupPrioritySms.getDestination());
        var expectedDemotedDefault =
                format(
                        """
                        {
                           "mfaIdentifier":"%s",
                           "priorityIdentifier":"BACKUP",
                           "methodVerified":true,
                           "method": {
                           "mfaMethodType":"SMS",
                             "phoneNumber":"%s"
                           }
                        }
                        """,
                        defaultPrioritySms.getMfaIdentifier(), defaultPrioritySms.getDestination());

        var expectedResponseBody =
                defaultPrioritySms.getMfaIdentifier().compareTo(backupMfaIdentifier) < 0
                        ? format("[%s,%s]", expectedDemotedDefault, expectedPromotedBackup)
                        : format("[%s,%s]", expectedPromotedBackup, expectedDemotedDefault);

        assertEquals(200, response.getStatusCode());

        var expectedResponse =
                JsonParser.parseString(expectedResponseBody).getAsJsonArray().toString();
        assertEquals(expectedResponse, response.getBody());

        var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);
        var retrievedDefault = getMethodWithPriority(retrievedMfaMethods, DEFAULT);
        var retrievedBackup = getMethodWithPriority(retrievedMfaMethods, BACKUP);

        assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                backupPrioritySms, retrievedDefault, DEFAULT);
        assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                defaultPrioritySms, retrievedBackup, BACKUP);
    }

    @Test
    void shouldReturn200AndMfaMethodDataWhenSmsUserUpdatesTheirPhoneNumber() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
        var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

        var mfaIdentifier = defaultPrioritySms.getMfaIdentifier();
        var updatedPhoneNumber = "07900000123";
        var updatedPhoneNumberWithCountryCode = "+447900000123";
        var updateRequest =
                format(
                        """
                                {
                                  "mfaMethod": {
                                    "priorityIdentifier": "DEFAULT",
                                    "method": {
                                        "mfaMethodType": "SMS",
                                        "phoneNumber": "%s",
                                        "otp": "%s"
                                    }
                                  }
                                }
                                """,
                        updatedPhoneNumber, otp);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                mfaIdentifier),
                        Map.of("principalId", testInternalSubject));

        var expectedUpdatedDefault =
                format(
                        """
                        {
                             "mfaIdentifier":"%s",
                             "priorityIdentifier":"DEFAULT",
                             "methodVerified":true,
                             "method": {
                               "mfaMethodType":"SMS",
                               "phoneNumber":"%s"
                             }
                         }
                        """,
                        mfaIdentifier, updatedPhoneNumberWithCountryCode);
        var expectedUnchangedBackup =
                format(
                        """
                        {
                           "mfaIdentifier":"%s",
                           "priorityIdentifier":"BACKUP",
                           "methodVerified":true,
                           "method": {
                           "mfaMethodType":"SMS",
                             "phoneNumber":"%s"
                           }
                        }
                        """,
                        backupPrioritySms.getMfaIdentifier(), TEST_PHONE_NUMBER_TWO);

        var expectedResponseBody =
                backupPrioritySms.getMfaIdentifier().compareTo(mfaIdentifier) < 0
                        ? format("[%s,%s]", expectedUnchangedBackup, expectedUpdatedDefault)
                        : format("[%s,%s]", expectedUpdatedDefault, expectedUnchangedBackup);

        assertEquals(200, response.getStatusCode());

        var expectedResponse =
                JsonParser.parseString(expectedResponseBody).getAsJsonArray().toString();
        assertEquals(expectedResponse, response.getBody());

        var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        assertEquals(2, retrievedMfaMethods.size());

        var retrievedDefault = getMethodWithPriority(retrievedMfaMethods, DEFAULT);

        assertRetrievedMethodHasSameBasicFields(defaultPrioritySms, retrievedDefault);
        assertMfaPhoneNumberUpdated(retrievedDefault, updatedPhoneNumberWithCountryCode);
    }

    @Test
    void duplicateUpdatesShouldBeIdempotentForUpdatesToDefaultMethod() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
        var mfaIdentifier = defaultPriorityAuthApp.getMfaIdentifier();
        var updatedCredential = "some-new-credential";
        var updateRequest =
                format(
                        """
                                {
                                  "mfaMethod": {
                                    "priorityIdentifier": "DEFAULT",
                                    "method": {
                                        "mfaMethodType": "AUTH_APP",
                                        "credential": "%s"
                                    }
                                  }
                                }
                                """,
                        updatedCredential);

        var firstResponse =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                mfaIdentifier),
                        Map.of("principalId", testInternalSubject));

        assertEquals(200, firstResponse.getStatusCode());

        var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        assertEquals(1, retrievedMfaMethods.size());

        var retrievedMethodAfterFirstRequest = retrievedMfaMethods.get(0);

        assertRetrievedMethodHasSameBasicFields(
                defaultPriorityAuthApp, retrievedMethodAfterFirstRequest);
        assertMfaCredentialUpdated(retrievedMethodAfterFirstRequest, updatedCredential);

        for (int i = 0; i < 5; i++) {
            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of(
                                    "publicSubjectId",
                                    testPublicSubject,
                                    "mfaIdentifier",
                                    mfaIdentifier),
                            Map.of("principalId", testInternalSubject));

            assertEquals(204, response.getStatusCode());

            var retrievedMethodsAfterSubsequentUpdates = userStore.getMfaMethod(TEST_EMAIL);

            assertEquals(1, retrievedMethodsAfterSubsequentUpdates.size());

            var retrievedMethod = retrievedMethodsAfterSubsequentUpdates.get(0);

            assertRetrievedMethodHasSameBasicFields(defaultPriorityAuthApp, retrievedMethod);
            assertEquals(
                    retrievedMethodAfterFirstRequest.getCredentialValue(),
                    retrievedMethod.getCredentialValue());
        }
    }

    @Test
    void cannotEditBackupMethod() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var mfaIdentifierOfBackup = backupPrioritySms.getMfaIdentifier();
        var updateRequest = buildUpdateRequestWithOtp();

        var requestPathParams =
                Map.ofEntries(
                        Map.entry("publicSubjectId", testPublicSubject),
                        Map.entry("mfaIdentifier", mfaIdentifierOfBackup));

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        requestPathParams,
                        Map.of("principalId", testInternalSubject));

        assertEquals(400, response.getStatusCode());

        var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        assertEquals(2, retrievedMfaMethods.size());

        assertRetrievedMethodHasSameBasicFields(
                defaultPriorityAuthApp, getMethodWithPriority(retrievedMfaMethods, DEFAULT));

        assertRetrievedMethodHasSameBasicFields(
                backupPrioritySms, getMethodWithPriority(retrievedMfaMethods, BACKUP));
  }

    private static String buildUpdateRequestWithOtp() {
        var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);
        return format(
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "DEFAULT",
                            "method": {
                                "mfaMethodType": "SMS",
                                "phoneNumber": "%s",
                                "otp": "%s"
                            }
                          }
                        }
                        """,
                backupPrioritySms.getDestination(), otp);
    }

    @Test
    void shouldReturn401WhenPrincipalIsInvalid() {
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                "mfaIdentifier"),
                        Map.of("principalId", "invalid-internal-subject-id"));

        assertEquals(401, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1079));
    }

    @Test
    void shouldReturn404WhenUserProfileIsNotFoundForPublicSubject() {
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                "invalid-public-subject-id",
                                "mfaIdentifier",
                                "mfa-identifier"),
                        Map.of("principalId", testInternalSubject));

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    private MFAMethod getMethodWithPriority(
            List<MFAMethod> mfaMethods, PriorityIdentifier priority) {
        return mfaMethods.stream()
                .filter(mfaMethod -> mfaMethod.getPriority().equals(priority.name()))
                .findFirst()
                .get();
    }

    private void assertRetrievedMethodHasSameBasicFields(MFAMethod expected, MFAMethod retrieved) {
        assertEquals(expected.getMfaMethodType(), retrieved.getMfaMethodType());
        assertEquals(expected.getPriority(), retrieved.getPriority());
        assertEquals(expected.getMfaIdentifier(), retrieved.getMfaIdentifier());
        assertEquals(expected.isEnabled(), retrieved.isEnabled());
        assertEquals(expected.isMethodVerified(), retrieved.isMethodVerified());
    }

    private void assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
            MFAMethod expected, MFAMethod retrieved, PriorityIdentifier expectedPriority) {
        assertEquals(expected.getMfaMethodType(), retrieved.getMfaMethodType());
        assertEquals(expectedPriority.name(), retrieved.getPriority());
        assertEquals(expected.getMfaIdentifier(), retrieved.getMfaIdentifier());
        assertEquals(expected.isEnabled(), retrieved.isEnabled());
        assertEquals(expected.isMethodVerified(), retrieved.isMethodVerified());
        assertEquals(expected.getCredentialValue(), retrieved.getCredentialValue());
        assertEquals(expected.getDestination(), retrieved.getDestination());
    }

    private void assertMfaCredentialUpdated(MFAMethod retrieved, String updatedCredential) {
        assertEquals(retrieved.getCredentialValue(), updatedCredential);
        assertNull(retrieved.getDestination());
    }

    private void assertMfaPhoneNumberUpdated(MFAMethod retrieved, String updatedPhone) {
        assertEquals(retrieved.getDestination(), updatedPhone);
        assertNull(retrieved.getCredentialValue());
    }
}
