package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.AssertionFailedError;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.mfa.response.ResponseAuthAppMfaDetail;
import uk.gov.di.accountmanagement.entity.mfa.response.ResponseSmsMfaDetail;
import uk.gov.di.accountmanagement.lambda.MFAMethodsCreateHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
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
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

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
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_FAILED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.entity.NotificationType.BACKUP_METHOD_ADDED;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_MFA_METHOD;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_MFA_TYPE;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_NOTIFICATION_TYPE;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
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
    public static final String EXTENSIONS_MFA_CODE_ENTERED =
            "extensions." + AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED;
    public static final String EXTENSIONS_ACCOUNT_RECOVERY =
            "extensions." + AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY;
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

        @DisplayName("Non-migrated User adds a Backup SMS MFA")
        @ParameterizedTest(name = "Default MFA: {0}")
        @MethodSource("defaultMfaMethodProvider")
        void aNonMigratedUserAddsABackupSMSMFA(String testName, MFAMethod defaultMfaMethod) {
            setupNonMigratedUserWithMfaMethod(defaultMfaMethod);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            // WHEN
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER_TWO, otp))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            // THEN
            assertEquals(
                    200,
                    response.getStatusCode(),
                    "Expected successful response for adding backup SMS MFA");

            assertUserMigrationStatus(true, "User should be migrated after adding backup MFA");

            var retrievedSmsMethod = findMfaMethodByPriority(BACKUP, "Missing BACKUP MFA");
            assertEquals(
                    TEST_PHONE_NUMBER_TWO_WITH_COUNTRY_CODE, retrievedSmsMethod.getDestination());
            assertTrue(retrievedSmsMethod.isEnabled());
            assertTrue(retrievedSmsMethod.isMethodVerified());

            var backupMfaIdentifier = retrievedSmsMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            backupMfaIdentifier,
                            BACKUP,
                            true,
                            new ResponseSmsMfaDetail(TEST_PHONE_NUMBER_TWO_WITH_COUNTRY_CODE));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    BACKUP_METHOD_ADDED,
                                    LocaleHelper.SupportedLanguage.EN)));

            // Check audit events
            List<AuditableEvent> expectedEvents =
                    List.of(
                            AUTH_UPDATE_PHONE_NUMBER,
                            AUTH_CODE_VERIFIED,
                            AUTH_MFA_METHOD_MIGRATION_ATTEMPTED,
                            AUTH_MFA_METHOD_ADD_COMPLETED);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> codeVerifiedAttributes = new HashMap<>();
            codeVerifiedAttributes.put(EXTENSIONS_MFA_CODE_ENTERED, otp);
            codeVerifiedAttributes.put(EXTENSIONS_ACCOUNT_RECOVERY, "false");
            codeVerifiedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_METHOD, BACKUP.name().toLowerCase());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_TYPE, SMS.name());
            codeVerifiedAttributes.put(EXTENSIONS_NOTIFICATION_TYPE, "MFA_SMS");
            eventExpectations.put(AUTH_CODE_VERIFIED.name(), codeVerifiedAttributes);

            Map<String, String> migrationAttributes = new HashMap<>();
            migrationAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            eventExpectations.put(AUTH_MFA_METHOD_MIGRATION_ATTEMPTED.name(), migrationAttributes);

            Map<String, String> addCompletedAttributes = new HashMap<>();
            addCompletedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addCompletedAttributes.put(EXTENSIONS_MFA_TYPE, SMS.name());
            addCompletedAttributes.put(EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE, "44");
            eventExpectations.put(AUTH_MFA_METHOD_ADD_COMPLETED.name(), addCompletedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
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

        @DisplayName("Migrated User adds a Backup SMS MFA")
        @ParameterizedTest(name = "Default MFA: {0}")
        @MethodSource("migratedMfaMethodProvider")
        void aMigratedUserAddsABackupSMSMFA(
                String testName,
                MFAMethod defaultMfaMethod,
                String phoneNumber,
                String phoneNumberWithCountryCode) {
            setupMigratedUserWithMfaMethod(defaultMfaMethod);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP, new RequestSmsMfaDetail(phoneNumber, otp))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    200,
                    response.getStatusCode(),
                    "Expected successful response for migrated user adding backup SMS MFA");

            assertUserMigrationStatus(true, "User should still be migrated");

            var retrievedSmsMethod = findMfaMethodByPriority(BACKUP, "Backup MFA method not found");
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
                            BACKUP,
                            true,
                            new ResponseSmsMfaDetail(phoneNumberWithCountryCode));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());

            List<AuditableEvent> expectedEvents =
                    List.of(
                            AUTH_CODE_VERIFIED,
                            AUTH_UPDATE_PHONE_NUMBER,
                            AUTH_MFA_METHOD_ADD_COMPLETED);

            Map<String, String> codeVerifiedAttributes = new HashMap<>();
            codeVerifiedAttributes.put(EXTENSIONS_MFA_CODE_ENTERED, otp);
            codeVerifiedAttributes.put(EXTENSIONS_ACCOUNT_RECOVERY, "false");
            codeVerifiedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_METHOD, BACKUP.name().toLowerCase());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_TYPE, SMS.name());
            codeVerifiedAttributes.put(EXTENSIONS_NOTIFICATION_TYPE, "MFA_SMS");

            Map<String, String> addCompletedAttributes = new HashMap<>();
            addCompletedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addCompletedAttributes.put(EXTENSIONS_MFA_TYPE, SMS.name());

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();
            eventExpectations.put(AUTH_CODE_VERIFIED.name(), codeVerifiedAttributes);
            eventExpectations.put(AUTH_MFA_METHOD_ADD_COMPLETED.name(), addCompletedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @DisplayName("Non-migrated SMS User adds a Backup AUTH_APP MFA")
        @Test
        void aNonMigratedSmsUserAddsABackupAuthAppMFA() {
            setupNonMigratedUserWithMfaMethod(defaultPrioritySms);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP, new RequestAuthAppMfaDetail(TEST_CREDENTIAL))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    200,
                    response.getStatusCode(),
                    "Expected successful response for non-migrated SMS user adding backup Auth App MFA");

            assertUserMigrationStatus(true, "User should be migrated after adding backup MFA");

            var retrievedAuthAppMethod =
                    findMfaMethodByPriority(BACKUP, "Backup Auth App MFA method not found");
            assertEquals(TEST_CREDENTIAL, retrievedAuthAppMethod.getCredentialValue());
            assertTrue(retrievedAuthAppMethod.isEnabled());
            assertTrue(retrievedAuthAppMethod.isMethodVerified());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    BACKUP_METHOD_ADDED,
                                    LocaleHelper.SupportedLanguage.EN)));

            var extractedMfaIdentifier = retrievedAuthAppMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            extractedMfaIdentifier,
                            BACKUP,
                            true,
                            new ResponseAuthAppMfaDetail(TEST_CREDENTIAL));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());

            // Check audit events
            List<AuditableEvent> expectedEvents =
                    List.of(
                            AUTH_CODE_VERIFIED,
                            AUTH_MFA_METHOD_MIGRATION_ATTEMPTED,
                            AUTH_MFA_METHOD_ADD_COMPLETED);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> codeVerifiedAttributes = new HashMap<>();
            codeVerifiedAttributes.put(EXTENSIONS_ACCOUNT_RECOVERY, "false");
            codeVerifiedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_METHOD, BACKUP.name().toLowerCase());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_CODE_VERIFIED.name(), codeVerifiedAttributes);

            Map<String, String> migrationAttributes = new HashMap<>();
            migrationAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            eventExpectations.put(AUTH_MFA_METHOD_MIGRATION_ATTEMPTED.name(), migrationAttributes);

            Map<String, String> addCompletedAttributes = new HashMap<>();
            addCompletedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addCompletedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_MFA_METHOD_ADD_COMPLETED.name(), addCompletedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @DisplayName("Migrated SMS User adds a Backup AUTH_APP MFA")
        @Test
        void aMigratedSmsUserAddsABackupAuthAppMFA() {
            setupMigratedUserWithMfaMethod(defaultPrioritySms);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP, new RequestAuthAppMfaDetail(TEST_CREDENTIAL))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    200,
                    response.getStatusCode(),
                    "Expected successful response for migrated SMS user adding backup Auth App MFA");

            assertUserMigrationStatus(true, "User should still be migrated");

            var retrievedAuthAppMethod =
                    findMfaMethodByPriority(BACKUP, "Backup Auth App MFA method not found");

            assertEquals(TEST_CREDENTIAL, retrievedAuthAppMethod.getCredentialValue());
            assertTrue(retrievedAuthAppMethod.isEnabled());
            assertTrue(retrievedAuthAppMethod.isMethodVerified());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    BACKUP_METHOD_ADDED,
                                    LocaleHelper.SupportedLanguage.EN)));

            var extractedMfaIdentifier = retrievedAuthAppMethod.getMfaIdentifier();
            var expectedJson =
                    constructExpectedResponse(
                            extractedMfaIdentifier,
                            BACKUP,
                            true,
                            new ResponseAuthAppMfaDetail(TEST_CREDENTIAL));
            var expectedResponse =
                    JsonParser.parseString(expectedJson).getAsJsonObject().toString();

            assertEquals(expectedResponse, response.getBody());

            List<AuditableEvent> expectedEvents =
                    List.of(AUTH_CODE_VERIFIED, AUTH_MFA_METHOD_ADD_COMPLETED);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> codeVerifiedAttributes = new HashMap<>();
            codeVerifiedAttributes.put(EXTENSIONS_ACCOUNT_RECOVERY, "false");
            codeVerifiedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_METHOD, BACKUP.name().toLowerCase());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_CODE_VERIFIED.name(), codeVerifiedAttributes);

            Map<String, String> addCompletedAttributes = new HashMap<>();
            addCompletedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addCompletedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_MFA_METHOD_ADD_COMPLETED.name(), addCompletedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }
    }

    @Nested
    class ErrorCases {
        @DisplayName("Migrated User enters invalid OTP when adding backup SMS MFA")
        @Test
        void shouldReturn400WhenInvalidOTPEnteredWhenAddingSMSBackupMFA() {
            setupMigratedUserWithMfaMethod(defaultPriorityAuthApp);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);
            var invalidOtp = otp + 1;

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            PriorityIdentifier.BACKUP,
                                            new RequestSmsMfaDetail(
                                                    TEST_PHONE_NUMBER, invalidOtp))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_OTP));

            List<AuditableEvent> expectedEvents = List.of(AUTH_INVALID_CODE_SENT);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> addInvalidCodeSentAttributes = new HashMap<>();
            addInvalidCodeSentAttributes.put(
                    EXTENSIONS_MFA_METHOD, PriorityIdentifier.BACKUP.name().toLowerCase());
            addInvalidCodeSentAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            eventExpectations.put(AUTH_INVALID_CODE_SENT.name(), addInvalidCodeSentAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @DisplayName("Migrated Auth App User cannot add Auth App as backup MFA")
        @Test
        void shouldReturn400ErrorWhenMigratedAuthAppUserAddsAuthAppBackup() {
            setupMigratedUserWithMfaMethod(defaultPriorityAuthApp);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestAuthAppMfaDetail(
                                                    "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected error response when migrated Auth App user adds Auth App as backup");
            assertThat(response, hasJsonBody(ErrorResponse.AUTH_APP_EXISTS));

            List<AuditableEvent> expectedEvents =
                    List.of(AUTH_CODE_VERIFIED, AUTH_MFA_METHOD_ADD_FAILED);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> codeVerifiedAttributes = new HashMap<>();
            codeVerifiedAttributes.put(EXTENSIONS_ACCOUNT_RECOVERY, "false");
            codeVerifiedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_METHOD, BACKUP.name().toLowerCase());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_CODE_VERIFIED.name(), codeVerifiedAttributes);

            Map<String, String> addFailedAttributes = new HashMap<>();
            addFailedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addFailedAttributes.put(EXTENSIONS_MFA_TYPE, MFAMethodType.AUTH_APP.name());
            addFailedAttributes.put(EXTENSIONS_MFA_METHOD, DEFAULT.name().toLowerCase());
            eventExpectations.put(AUTH_MFA_METHOD_ADD_FAILED.name(), addFailedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @DisplayName("Non-migrated Auth App User cannot add Auth App as backup MFA")
        @Test
        void shouldReturn400ErrorWhenNonMigratedAuthAppUserAddsAuthAppBackup() {
            setupNonMigratedUserWithMfaMethod(defaultPriorityAuthApp);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestAuthAppMfaDetail(
                                                    "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected error response when non-migrated Auth App user adds Auth App as backup");
            assertThat(response, hasJsonBody(ErrorResponse.AUTH_APP_EXISTS));

            // Verify user is now migrated after the request (even though it failed)
            assertUserMigrationStatus(true, "User should be migrated despite failure");

            List<AuditableEvent> expectedEvents =
                    List.of(
                            AUTH_CODE_VERIFIED,
                            AUTH_MFA_METHOD_MIGRATION_ATTEMPTED,
                            AUTH_MFA_METHOD_ADD_FAILED);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> codeVerifiedAttributes = new HashMap<>();
            codeVerifiedAttributes.put(EXTENSIONS_ACCOUNT_RECOVERY, "false");
            codeVerifiedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_METHOD, BACKUP.name().toLowerCase());
            codeVerifiedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_CODE_VERIFIED.name(), codeVerifiedAttributes);

            Map<String, String> migrationAttributes = new HashMap<>();
            migrationAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            eventExpectations.put(AUTH_MFA_METHOD_MIGRATION_ATTEMPTED.name(), migrationAttributes);

            Map<String, String> addFailedAttributes = new HashMap<>();
            addFailedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addFailedAttributes.put(EXTENSIONS_MFA_TYPE, MFAMethodType.AUTH_APP.name());
            addFailedAttributes.put(
                    EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name().toLowerCase());
            eventExpectations.put(AUTH_MFA_METHOD_ADD_FAILED.name(), addFailedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @Test
        void shouldReturn400AndBadRequestWhenPathParameterIsNotPresent() {
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                            Collections.emptyMap(),
                            Collections.emptyMap());
            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected bad request when path parameter is not present");
            assertThat(response, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @Test
        void shouldReturn400AndBadRequestWhenPublicSubjectIsNotInUserStore() {
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", "incorrect-public-subject-id"),
                            Map.of("principalId", testInternalSubject));
            assertEquals(
                    404,
                    response.getStatusCode(),
                    "Expected not found when public subject is not in user store");
            assertThat(response, hasJsonBody(ErrorResponse.USER_NOT_FOUND));
        }

        private static Stream<MFAMethodType> invalidMfaMethodTypes() {
            return Stream.of(MFAMethodType.EMAIL, MFAMethodType.NONE);
        }

        @ParameterizedTest
        @MethodSource("invalidMfaMethodTypes")
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
            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected bad request when MFA method type is invalid");
            assertThat(response, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @Test
        void shouldReturn400ErrorResponseWhenAddingMfaAfterMfaCountLimitReached() {
            setupMigratedUserWithMfaMethod(defaultPrioritySms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, otp))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected error response when MFA count limit is reached");
            assertThat(response, hasJsonBody(ErrorResponse.MFA_METHOD_COUNT_LIMIT_REACHED));
        }

        @Test
        void shouldReturn400ErrorResponseWhenSmsUserAddsSmsMfaWithSamePhoneNumber() {
            setupMigratedUserWithMfaMethod(defaultPrioritySms);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, otp))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected error response when adding SMS MFA with same phone number");
            assertThat(response, hasJsonBody(ErrorResponse.SMS_MFA_WITH_NUMBER_EXISTS));
        }

        @Test
        @DisplayName("Should return 400 when phone number is invalid")
        void shouldReturn400ErrorResponseWhenPhoneNumberIsInvalid() {
            setupMigratedUserWithMfaMethod(defaultPriorityAuthApp);
            String invalidPhoneNumber = "invalid-phone-number";
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestSmsMfaDetail(invalidPhoneNumber, otp))),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", testInternalSubject));

            assertEquals(
                    400,
                    response.getStatusCode(),
                    "Expected error response when phone number is invalid");
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));

            // Check audit events
            List<AuditableEvent> expectedEvents = List.of(AUTH_MFA_METHOD_ADD_FAILED);

            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> addFailedAttributes = new HashMap<>();
            addFailedAttributes.put(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            addFailedAttributes.put(EXTENSIONS_MFA_METHOD, DEFAULT.name().toLowerCase());
            addFailedAttributes.put(EXTENSIONS_MFA_TYPE, AUTH_APP.name());
            eventExpectations.put(AUTH_MFA_METHOD_ADD_FAILED.name(), addFailedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @Test
        void shouldReturn401WhenPrincipalIsInvalid() {
            var response =
                    makeRequest(
                            Optional.of(
                                    constructRequestBody(
                                            BACKUP,
                                            new RequestAuthAppMfaDetail(
                                                    AUTH_APP,
                                                    "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", testPublicSubject),
                            Map.of("principalId", "invalid"));

            assertEquals(
                    401,
                    response.getStatusCode(),
                    "Expected unauthorized when principal is invalid");
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_PRINCIPAL));
        }
    }

    private void assertUserMigrationStatus(boolean expectedMigrationStatus, String message) {
        var userProfile =
                userStore
                        .getUserProfileFromEmail(TEST_EMAIL)
                        .orElseThrow(() -> new AssertionFailedError("User profile not found"));
        if (expectedMigrationStatus) {
            assertTrue(userProfile.isMfaMethodsMigrated(), message);
        } else {
            assertFalse(userProfile.isMfaMethodsMigrated(), message);
        }
    }

    private MFAMethod findMfaMethodByPriority(PriorityIdentifier priority, String errorMessage) {
        List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);
        return mfaMethods.stream()
                .filter(mfaMethod -> mfaMethod.getPriority().equals(priority.name()))
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError(errorMessage));
    }

    private void setupNonMigratedUserWithMfaMethod(MFAMethod mfaMethod) {
        if (mfaMethod.getMfaMethodType().equalsIgnoreCase("AUTH_APP")) {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, mfaMethod);
        } else {
            userStore.addVerifiedPhoneNumber(TEST_EMAIL, mfaMethod.getDestination());
        }
        userStore.setMfaMethodsMigrated(TEST_EMAIL, false);

        // Verify user is not migrated
        assertUserMigrationStatus(false, "User should not be migrated");
    }

    private void setupMigratedUserWithMfaMethod(MFAMethod mfaMethod) {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, mfaMethod);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        // Verify user is migrated
        assertUserMigrationStatus(true, "User should be migrated");
    }

    private void verifyAuditEvents(
            List<AuditableEvent> expectedEvents,
            Map<String, Map<String, String>> eventExpectations) {
        // Assert that the expected events were received
        List<String> receivedEvents = assertTxmaAuditEventsReceived(txmaAuditQueue, expectedEvents);

        // Create and verify expectations for each event
        for (Map.Entry<String, Map<String, String>> eventEntry : eventExpectations.entrySet()) {
            String eventName = eventEntry.getKey();
            Map<String, String> attributes = eventEntry.getValue();

            // Create the expectation for this event
            AuditEventExpectation expectation =
                    new AuditEventExpectation(AccountManagementAuditableEvent.valueOf(eventName));

            // Add all expected attributes
            for (Map.Entry<String, String> attributeEntry : attributes.entrySet()) {
                expectation.withAttribute(attributeEntry.getKey(), attributeEntry.getValue());
            }

            // Verify the expectation against the received events
            expectation.verify(receivedEvents);
        }
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
