package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.mfa.response.ResponseAuthAppMfaDetail;
import uk.gov.di.accountmanagement.entity.mfa.response.ResponseSmsMfaDetail;
import uk.gov.di.accountmanagement.lambda.MFAMethodsCreateHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED;
import static uk.gov.di.accountmanagement.entity.NotificationType.BACKUP_METHOD_ADDED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsCreateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "07700900000";
    private static final String TEST_PHONE_NUMBER_WITH_COUNTRY_CODE = "+447700900000";
    private static final String TEST_PHONE_NUMBER_TWO = "07700900111";
    private static final String TEST_PHONE_NUMBER_TWO_WITH_COUNTRY_CODE = "+447700900111";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static String testPublicSubject;
    private static String testInternalSubject;
    private static final MFAMethod defaultPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    TEST_PHONE_NUMBER_WITH_COUNTRY_CODE,
                    PriorityIdentifier.DEFAULT,
                    UUID.randomUUID().toString());
    private static final MFAMethod backupPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    TEST_PHONE_NUMBER_TWO,
                    PriorityIdentifier.BACKUP,
                    UUID.randomUUID().toString());
    private static final MFAMethod defaultPriorityAuthApp =
            MFAMethod.authAppMfaMethod(
                    TEST_CREDENTIAL,
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    UUID.randomUUID().toString());

    @BeforeEach
    void setUp() {
        handler = new MFAMethodsCreateHandler(ACCOUNT_MANAGEMENT_TXMA_ENABLED_CONFIGUARION_SERVICE);
        userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        testPublicSubject =
                userStore.getUserProfileFromEmail(TEST_EMAIL).get().getPublicSubjectID();
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        testInternalSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userStore.getUserProfileFromEmail(TEST_EMAIL).get().getSubjectID(),
                        INTERNAL_SECTOR_HOST,
                        salt);
        notificationsQueue.clear();
        txmaAuditQueue.clear();
    }

    @Nested
    class SuccessfulMFACreation {
        private static Stream<Arguments> defaultMfaMethodProvider() {
            return Stream.of(
                    Arguments.of("Auth App", defaultPriorityAuthApp),
                    Arguments.of("SMS", defaultPrioritySms));
        }

        @DisplayName("Non-migrated user adds a backup SMS MFA")
        @ParameterizedTest(name = "Default MFA: {0}")
        @MethodSource("defaultMfaMethodProvider")
        void aNonMigratedUserAddsABackupSMSMFA(String testName, MFAMethod defaultMfaMethod) {
            if (defaultMfaMethod.getMfaMethodType().equalsIgnoreCase("AUTH_APP")) {
                userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultMfaMethod);
            } else {
                userStore.addVerifiedPhoneNumber(TEST_EMAIL, defaultMfaMethod.getDestination());
            }
            userStore.setMfaMethodsMigrated(TEST_EMAIL, false);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            // Verify user is not migrated before the request
            var userProfileBefore = userStore.getUserProfileFromEmail(TEST_EMAIL).get();
            assertFalse(userProfileBefore.isMfaMethodsMigrated());

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER_TWO, otp))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            // Verify user is now migrated after the request
            var userProfileAfter = userStore.getUserProfileFromEmail(TEST_EMAIL).get();
            assertTrue(userProfileAfter.isMfaMethodsMigrated());

            var retrievedSmsMethod =
                    mfaMethods.stream()
                            .filter(
                                    mfaMethod ->
                                            mfaMethod
                                                    .getPriority()
                                                    .equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();

            assertEquals(PriorityIdentifier.BACKUP.toString(), retrievedSmsMethod.getPriority());
            assertEquals(
                    TEST_PHONE_NUMBER_TWO_WITH_COUNTRY_CODE, retrievedSmsMethod.getDestination());
            assertTrue(retrievedSmsMethod.isEnabled());
            assertTrue(retrievedSmsMethod.isMethodVerified());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    BACKUP_METHOD_ADDED,
                                    LocaleHelper.SupportedLanguage.EN)));

            var extractedMfaIdentifier = retrievedSmsMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            extractedMfaIdentifier,
                            PriorityIdentifier.BACKUP,
                            true,
                            new ResponseSmsMfaDetail(TEST_PHONE_NUMBER_TWO_WITH_COUNTRY_CODE));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());

            // Verify audit event was emitted
            var receivedEvents =
                    assertTxmaAuditEventsReceived(
                            txmaAuditQueue, List.of(AUTH_MFA_METHOD_ADD_COMPLETED));

            // Verify audit event contains correct metadata
            var auditEvent = receivedEvents.get(0);
            var jsonEvent = JsonParser.parseString(auditEvent).getAsJsonObject();

            var extensions = jsonEvent.getAsJsonObject("extensions");

            // Check MFA type based on the default MFA method
            String expectedMfaType = defaultMfaMethod.getMfaMethodType();
            assertEquals(
                    expectedMfaType, extensions.get(AUDIT_EVENT_EXTENSIONS_MFA_TYPE).getAsString());

            // Check for phone number dialing code prefix if the default MFA is SMS
            if (expectedMfaType.equals(MFAMethodType.SMS.getValue())) {
                assertTrue(extensions.has("phone_number_country_code"));
                assertEquals("44", extensions.get("phone_number_country_code").getAsString());
            }

            assertEquals(
                    ACCOUNT_MANAGEMENT.name(),
                    extensions.get(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE).getAsString());
        }

        private static Stream<Arguments> migratedMfaMethodProvider() {
            return Stream.of(
                    Arguments.of(
                            "Auth App",
                            defaultPriorityAuthApp,
                            TEST_PHONE_NUMBER,
                            TEST_PHONE_NUMBER_WITH_COUNTRY_CODE),
                    Arguments.of(
                            "SMS",
                            defaultPrioritySms,
                            TEST_PHONE_NUMBER_TWO,
                            TEST_PHONE_NUMBER_TWO_WITH_COUNTRY_CODE));
        }

        @DisplayName("Migrated user adds a backup SMS MFA")
        @ParameterizedTest(name = "Default MFA: {0}")
        @MethodSource("migratedMfaMethodProvider")
        void aMigratedUserAddsABackupSMSMFA(
                String testName,
                MFAMethod defaultMfaMethod,
                String phoneNumber,
                String phoneNumberWithCountryCode) {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultMfaMethod);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(phoneNumber, otp))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            // Verify user is still migrated
            assertTrue(userStore.getUserProfileFromEmail(TEST_EMAIL).get().isMfaMethodsMigrated());

            var retrievedSmsMethod =
                    mfaMethods.stream()
                            .filter(
                                    mfaMethod ->
                                            mfaMethod
                                                    .getPriority()
                                                    .equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();

            assertEquals(PriorityIdentifier.BACKUP.toString(), retrievedSmsMethod.getPriority());
            assertEquals(phoneNumberWithCountryCode, retrievedSmsMethod.getDestination());
            assertTrue(retrievedSmsMethod.isEnabled());
            assertTrue(retrievedSmsMethod.isMethodVerified());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    BACKUP_METHOD_ADDED,
                                    LocaleHelper.SupportedLanguage.EN)));

            var extractedMfaIdentifier = retrievedSmsMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            extractedMfaIdentifier,
                            PriorityIdentifier.BACKUP,
                            true,
                            new ResponseSmsMfaDetail(phoneNumberWithCountryCode));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());

            // Verify audit event was emitted
            var receivedEvents =
                    assertTxmaAuditEventsReceived(
                            txmaAuditQueue, List.of(AUTH_MFA_METHOD_ADD_COMPLETED));

            // Verify audit event contains correct metadata
            var auditEvent = receivedEvents.get(0);
            var jsonEvent = JsonParser.parseString(auditEvent).getAsJsonObject();

            var extensions = jsonEvent.getAsJsonObject("extensions");

            // Check MFA type based on the default MFA method
            String expectedMfaType = defaultMfaMethod.getMfaMethodType();
            assertEquals(
                    expectedMfaType, extensions.get(AUDIT_EVENT_EXTENSIONS_MFA_TYPE).getAsString());

            // Check for phone number dialing code prefix if the default MFA is SMS
            if (expectedMfaType.equals(MFAMethodType.SMS.getValue())) {
                assertTrue(extensions.has("phone_number_country_code"));
                assertEquals("44", extensions.get("phone_number_country_code").getAsString());
            }

            assertEquals(
                    ACCOUNT_MANAGEMENT.name(),
                    extensions.get(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE).getAsString());
        }

        @Test
        void shouldReturn200AndMfaMethodDataWhenAuthAppUserAddsSmsMfa() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, otp))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            var retrievedSmsMethod =
                    mfaMethods.stream()
                            .filter(
                                    mfaMethod ->
                                            mfaMethod
                                                    .getMfaMethodType()
                                                    .equals(MFAMethodType.SMS.getValue()))
                            .findFirst()
                            .get();

            assertEquals(PriorityIdentifier.BACKUP.toString(), retrievedSmsMethod.getPriority());
            assertEquals(TEST_PHONE_NUMBER_WITH_COUNTRY_CODE, retrievedSmsMethod.getDestination());
            assertTrue(retrievedSmsMethod.isEnabled());
            assertTrue(retrievedSmsMethod.isMethodVerified());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    BACKUP_METHOD_ADDED,
                                    LocaleHelper.SupportedLanguage.EN)));

            var extractedMfaIdentifier = retrievedSmsMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            extractedMfaIdentifier,
                            PriorityIdentifier.BACKUP,
                            true,
                            new ResponseSmsMfaDetail(TEST_PHONE_NUMBER_WITH_COUNTRY_CODE));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());
        }

        @Test
        void shouldReturn200AndMfaMethodDataWhenSmsUserAddsAuthAppMfa() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));
            assertEquals(200, response.getStatusCode());

            List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            var retrievedAuthAppMethod =
                    mfaMethods.stream()
                            .filter(
                                    mfaMethod ->
                                            mfaMethod
                                                    .getMfaMethodType()
                                                    .equals(MFAMethodType.AUTH_APP.getValue()))
                            .findFirst()
                            .get();

            assertEquals(TEST_CREDENTIAL, retrievedAuthAppMethod.getCredentialValue());
            assertEquals(
                    PriorityIdentifier.BACKUP.toString(), retrievedAuthAppMethod.getPriority());
            assertTrue(retrievedAuthAppMethod.isEnabled());
            assertTrue(retrievedAuthAppMethod.isMethodVerified());

            var extractedMfaIdentifier = retrievedAuthAppMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            extractedMfaIdentifier,
                            PriorityIdentifier.BACKUP,
                            true,
                            new ResponseAuthAppMfaDetail(TEST_CREDENTIAL));

            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());
        }
    }

    @Nested
    class ErrorCases {
        @Test
        void shouldReturn400AndBadRequestWhenPathParameterIsNotPresent() {
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                            Collections.emptyMap(),
                            Collections.emptyMap());
            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
        }

        @Test
        void shouldReturn400AndBadRequestWhenPublicSubjectIsNotInUserStore() {
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", "incorrect-public-subject-id"),
                            Map.of("principalId", testInternalSubject));
            assertEquals(404, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
        }

        @ParameterizedTest
        @MethodSource(
                "uk.gov.di.accountmanagement.api.MFAMethodsCreateHandlerIntegrationTest#invalidMfaMethodTypes")
        void shouldReturn400AndBadRequestWhenMfaMethodTypeIsInvalid(
                MFAMethodType invalidMethodType) {
            var response =
                    makeRequest(
                            Optional.of(
                                    format(
                                            """
                                                    {
                                                      "mfaMethod": {
                                                        "priorityIdentifier": "BACKUP",
                                                        "method": {
                                                           "mfaMethodType": "%s",
                                                           "phoneNumber": "07900000000"
                                                        }
                                                      }
                                                    }
                                                    """,
                                            invalidMethodType)),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));
            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
        }

        @Test
        void shouldReturn400ErrorResponseWhenAddingMfaAfterMfaCountLimitReached() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, otp))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1068));
        }

        @Test
        void shouldReturn400ErrorResponseWhenSmsUserAddsSmsMfaWithSamePhoneNumber() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, otp))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1069));
        }

        @Test
        void shouldReturn400ErrorResponseWhenAuthAppAddsSecondAuthApp() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestAuthAppMfaDetail(
                                                    "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1070));
        }

        @Test
        void shouldReturn401WhenPrincipalIsInvalid() {
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestAuthAppMfaDetail(
                                                    MFAMethodType.AUTH_APP,
                                                    "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", "invalid"));

            assertEquals(401, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1079));
        }
    }

    private static Stream<MFAMethodType> invalidMfaMethodTypes() {
        return Stream.of(MFAMethodType.EMAIL, MFAMethodType.NONE);
    }

    private static String constructRequestBody(
            PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail) {
        return format(
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "%s",
                            "method": %s
                          }
                        }
                        """,
                priorityIdentifier, constructRequestMfaDetailJson(mfaDetail));
    }

    private static String constructExpectedResponse(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            MfaDetail mfaDetail) {
        return format(
                """
                        {
                          "mfaIdentifier": "%s",
                          "priorityIdentifier": "%s",
                          "methodVerified": %s,
                          "method": %s
                        }
                        """,
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                constructResponseMfaDetailJson(mfaDetail));
    }

    private static String constructResponseMfaDetailJson(MfaDetail mfaDetail) {
        if (mfaDetail instanceof ResponseSmsMfaDetail) {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "phoneNumber": "%s"
                            }
                            """,
                    (mfaDetail).mfaMethodType(), ((ResponseSmsMfaDetail) mfaDetail).phoneNumber());
        } else {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "credential": "%s"
                            }
                            """,
                    ((ResponseAuthAppMfaDetail) mfaDetail).mfaMethodType(),
                    ((ResponseAuthAppMfaDetail) mfaDetail).credential());
        }
    }

    private static String constructRequestMfaDetailJson(MfaDetail mfaDetail) {
        if (mfaDetail instanceof RequestSmsMfaDetail) {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "phoneNumber": "%s",
                              "otp": "%s"
                            }
                            """,
                    ((RequestSmsMfaDetail) mfaDetail).mfaMethodType(),
                    ((RequestSmsMfaDetail) mfaDetail).phoneNumber(),
                    ((RequestSmsMfaDetail) mfaDetail).otp());
        } else {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "credential": "%s"
                            }
                            """,
                    ((RequestAuthAppMfaDetail) mfaDetail).mfaMethodType(),
                    ((RequestAuthAppMfaDetail) mfaDetail).credential());
        }
    }
}
