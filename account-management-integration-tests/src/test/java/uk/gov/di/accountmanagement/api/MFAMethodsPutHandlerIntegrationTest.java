package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.MFAMethodsPutHandler;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;

class MFAMethodsPutHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "07700900000";
    private static final String TEST_PHONE_NUMBER_TWO = "07700900111";
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
        userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        testPublicSubject =
                userStore.getUserProfileFromEmail(TEST_EMAIL).get().getPublicSubjectID();
    }

    @Test
    void shouldReturn200AndMfaMethodDataWhenAuthAppUserUpdatesTheirCredential() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
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
                                mfaIdentifier));

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
    void shouldReturn200AndMfaMethodDataWhenSmsUserUpdatesTheirPhoneNumber() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
        var mfaIdentifier = defaultPrioritySms.getMfaIdentifier();
        var updatedPhoneNumber = "111222333";
        var updateRequest =
                format(
                        """
                                {
                                  "mfaMethod": {
                                    "priorityIdentifier": "DEFAULT",
                                    "method": {
                                        "mfaMethodType": "SMS",
                                        "phoneNumber": "%s"
                                    }
                                  }
                                }
                                """,
                        updatedPhoneNumber);

        var response =
                makeRequest(
                        Optional.of(updateRequest),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                testPublicSubject,
                                "mfaIdentifier",
                                mfaIdentifier));

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
                        mfaIdentifier, updatedPhoneNumber);
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

        var retrievedDefault =
                retrievedMfaMethods.stream()
                        .filter(mfaMethod -> mfaMethod.getPriority().equals(DEFAULT.name()))
                        .findFirst()
                        .get();

        assertRetrievedMethodHasSameBasicFields(defaultPrioritySms, retrievedDefault);
        assertMfaPhoneNumberUpdated(retrievedDefault, updatedPhoneNumber);
    }

    @Test
    void duplicateUpdatesShouldBeIdempotent() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
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
                                mfaIdentifier));

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
                                    mfaIdentifier));

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

    private void assertRetrievedMethodHasSameBasicFields(MFAMethod expected, MFAMethod retrieved) {
        assertEquals(expected.getMfaMethodType(), retrieved.getMfaMethodType());
        assertEquals(expected.getPriority(), retrieved.getPriority());
        assertEquals(expected.getMfaIdentifier(), retrieved.getMfaIdentifier());
        assertEquals(expected.isEnabled(), retrieved.isEnabled());
        assertEquals(expected.isMethodVerified(), retrieved.isMethodVerified());
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
