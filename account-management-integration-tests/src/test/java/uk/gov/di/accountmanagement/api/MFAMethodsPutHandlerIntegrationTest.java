package uk.gov.di.accountmanagement.api;

import net.javacrumbs.jsonunit.core.Option;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.lambda.MFAMethodsPutHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodNotificationIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.accountmanagement.entity.NotificationType.CHANGED_DEFAULT_MFA;
import static uk.gov.di.accountmanagement.entity.NotificationType.SWITCHED_MFA_METHODS;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsPutHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    public static final String UPDATE_SMS_METHOD_REQUEST_TEMPLATE =
            """
            {
              "mfaMethod": {
                "priorityIdentifier": "DEFAULT",
                "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s",
                    "otp": "%s"
                }
              },
              "notificationIdentifier": "%s"
            }
            """;
    public static final String UPDATE_MFA_TO_AUTH_APP_REQUEST_TEMPLATE =
            """
            {
              "mfaMethod": {
                "priorityIdentifier": "DEFAULT",
                "method": {
                    "mfaMethodType": "AUTH_APP",
                    "credential": "%s"
                }
              },
              "notificationIdentifier": "%s"
            }
            """;
    private static String testInternalSubject;

    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "+447700900000";
    private static final String TEST_PHONE_NUMBER_TWO = "+447700900111";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static String testPublicSubject;
    private static final MFAMethod defaultSms =
            MFAMethod.smsMfaMethod(
                    true, true, TEST_PHONE_NUMBER, DEFAULT, UUID.randomUUID().toString());
    private static final MFAMethod backupSms =
            MFAMethod.smsMfaMethod(
                    true, true, TEST_PHONE_NUMBER_TWO, BACKUP, UUID.randomUUID().toString());
    private static final MFAMethod defaultAuthApp =
            MFAMethod.authAppMfaMethod(
                    TEST_CREDENTIAL, true, true, DEFAULT, UUID.randomUUID().toString());
    private static final MFAMethod backupAuthApp =
            MFAMethod.authAppMfaMethod(
                    TEST_CREDENTIAL, true, true, BACKUP, UUID.randomUUID().toString());

    @BeforeEach
    void setUp() {
        testPublicSubject = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        var userProfileMaybe = userStore.getUserProfileFromEmail(TEST_EMAIL);
        var userProfile =
                userProfileMaybe.orElseThrow(
                        () -> new RuntimeException("could not create user profile"));
        testInternalSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userProfile.getSubjectID(), INTERNAL_SECTOR_HOST, salt);

        handler = new MFAMethodsPutHandler(ACCOUNT_MANAGEMENT_TXMA_ENABLED_CONFIGUARION_SERVICE);

        notificationsQueue.clear();
    }

    private MFAMethod getMethodWithPriority(
            List<MFAMethod> mfaMethods, PriorityIdentifier priority) {
        return mfaMethods.stream()
                .filter(mfaMethod -> mfaMethod.getPriority().equals(priority.name()))
                .findFirst()
                .get();
    }

    private void assertRetrievedMethodHasSameBasicFields(MFAMethod expected, MFAMethod retrieved) {
        assertAll(
                () -> assertEquals(expected.getMfaMethodType(), retrieved.getMfaMethodType()),
                () -> assertEquals(expected.getPriority(), retrieved.getPriority()),
                () -> assertEquals(expected.getMfaIdentifier(), retrieved.getMfaIdentifier()),
                () -> assertEquals(expected.isEnabled(), retrieved.isEnabled()),
                () -> assertEquals(expected.isMethodVerified(), retrieved.isMethodVerified()));
    }

    private void assertMfaCredentialUpdated(MFAMethod retrieved, String updatedCredential) {
        assertAll(
                () -> assertEquals(retrieved.getCredentialValue(), updatedCredential),
                () -> assertNull(retrieved.getDestination()));
    }

    @Nested
    class ChangingDefaultMethod {
        public static final MFAMethodNotificationIdentifier notificationIdentifier =
                MFAMethodNotificationIdentifier.CHANGED_DEFAULT_MFA;

        public static final String DEFAULT_AUTH_APP_RESPONSE_TEMPLATE =
                """
                [
                    {
                        "mfaIdentifier":"%s",
                        "priorityIdentifier":"DEFAULT",
                        "methodVerified":true,
                        "method": {
                          "mfaMethodType":"AUTH_APP",
                          "credential":"%s"
                        }
                    }
                ]
                """;

        public static final String SMS_RESPONSE_TEMPLATE =
                """
                {
                     "mfaIdentifier":"%s",
                     "priorityIdentifier":"%s",
                     "methodVerified":true,
                     "method": {
                       "mfaMethodType":"SMS",
                       "phoneNumber":"%s"
                     }
                 }
                """;

        @Test
        void canChangeAuthAppMethod() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultAuthApp);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var mfaIdentifier = defaultAuthApp.getMfaIdentifier();
            var updatedCredential = "some-new-credential";
            var updateRequest =
                    format(
                            UPDATE_MFA_TO_AUTH_APP_REQUEST_TEMPLATE,
                            updatedCredential,
                            notificationIdentifier.getValue());

            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            assertThatJson(response.getBody())
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(
                            DEFAULT_AUTH_APP_RESPONSE_TEMPLATE.formatted(
                                    mfaIdentifier, updatedCredential));

            var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            assertEquals(1, retrievedMfaMethods.size());

            var retrievedMethod = retrievedMfaMethods.get(0);

            assertRetrievedMethodHasSameBasicFields(defaultAuthApp, retrievedMethod);
            assertMfaCredentialUpdated(retrievedMethod, updatedCredential);

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    CHANGED_DEFAULT_MFA,
                                    LocaleHelper.SupportedLanguage.EN)));
        }

        @Test
        void canChangeSmsMethod() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultSms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupSms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var mfaIdentifier = defaultSms.getMfaIdentifier();
            var updatedPhoneNumber = "07900000123";
            var updatedPhoneNumberWithCountryCode = "+447900000123";
            var updateRequest =
                    format(
                            UPDATE_SMS_METHOD_REQUEST_TEMPLATE,
                            updatedPhoneNumber,
                            otp,
                            notificationIdentifier.getValue());

            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            var expectedUpdatedDefault =
                    format(
                            SMS_RESPONSE_TEMPLATE,
                            mfaIdentifier,
                            DEFAULT,
                            updatedPhoneNumberWithCountryCode);

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
                            backupSms.getMfaIdentifier(), TEST_PHONE_NUMBER_TWO);

            assertThatJson(response.getBody())
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(format("[%s,%s]", expectedUnchangedBackup, expectedUpdatedDefault));

            var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            assertEquals(2, retrievedMfaMethods.size());

            var retrievedDefault = getMethodWithPriority(retrievedMfaMethods, DEFAULT);

            assertRetrievedMethodHasSameBasicFields(defaultSms, retrievedDefault);

            assertAll(
                    () ->
                            assertEquals(
                                    updatedPhoneNumberWithCountryCode,
                                    retrievedDefault.getDestination()),
                    () -> assertNull(retrievedDefault.getCredentialValue()));

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    CHANGED_DEFAULT_MFA,
                                    LocaleHelper.SupportedLanguage.EN)));
        }

        @Test
        void canChangeDefaultFromAuthAppToSMS() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultAuthApp);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupSms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);
            var updateRequest =
                    format(
                            UPDATE_SMS_METHOD_REQUEST_TEMPLATE,
                            "+447900000123",
                            otp,
                            notificationIdentifier.getValue());
            var mfaIdentifier = defaultAuthApp.getMfaIdentifier();

            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            var expectedDefault =
                    format(SMS_RESPONSE_TEMPLATE, mfaIdentifier, DEFAULT, "+447900000123");

            var expectedBackup =
                    format(
                            SMS_RESPONSE_TEMPLATE,
                            backupSms.getMfaIdentifier(),
                            BACKUP,
                            backupSms.getDestination());

            assertThatJson(response.getBody())
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(format("[%s,%s]", expectedBackup, expectedDefault));

            var userCredentials = userStore.getUserCredentialsFromEmail(TEST_EMAIL);

            assertTrue(userCredentials.isPresent());

            var defaultMfa =
                    userCredentials.get().getMfaMethods().stream()
                            .filter(method -> Objects.equals(method.getPriority(), DEFAULT.name()))
                            .findFirst();

            assertTrue(defaultMfa.isPresent());
            assertAll(
                    () -> assertEquals(SMS.name(), defaultMfa.get().getMfaMethodType()),
                    () -> assertNull(defaultMfa.get().getCredentialValue()),
                    () -> assertEquals("+447900000123", defaultMfa.get().getDestination()));

            var maybeBackupMfa =
                    userCredentials.get().getMfaMethods().stream()
                            .filter(method -> Objects.equals(method.getPriority(), BACKUP.name()))
                            .findFirst();

            assertTrue(maybeBackupMfa.isPresent());
            var backupMfa = maybeBackupMfa.get();
            assertAll(
                    () -> assertEquals(SMS.name(), backupMfa.getMfaMethodType()),
                    () -> assertNull(backupMfa.getCredentialValue()),
                    () -> assertEquals(backupSms.getDestination(), backupMfa.getDestination()));

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    CHANGED_DEFAULT_MFA,
                                    LocaleHelper.SupportedLanguage.EN)));
        }

        @Test
        void canChangeDefaultFromSMSToAuthApp() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultSms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupSms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var updateRequest =
                    format(
                            UPDATE_MFA_TO_AUTH_APP_REQUEST_TEMPLATE,
                            "new-cred-AAAAAABBBBBCCCC",
                            notificationIdentifier.getValue());
            var mfaIdentifier = defaultSms.getMfaIdentifier();

            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            var userCredentials = userStore.getUserCredentialsFromEmail(TEST_EMAIL);

            assertTrue(userCredentials.isPresent());

            var defaultMfa =
                    userCredentials.get().getMfaMethods().stream()
                            .filter(method -> Objects.equals(method.getPriority(), DEFAULT.name()))
                            .findFirst();

            assertTrue(defaultMfa.isPresent());
            assertAll(
                    () ->
                            assertEquals(
                                    MFAMethodType.AUTH_APP.name(),
                                    defaultMfa.get().getMfaMethodType()),
                    () -> assertNull(defaultMfa.get().getDestination()),
                    () ->
                            assertEquals(
                                    "new-cred-AAAAAABBBBBCCCC",
                                    defaultMfa.get().getCredentialValue()));

            var backupMfa =
                    userCredentials.get().getMfaMethods().stream()
                            .filter(method -> Objects.equals(method.getPriority(), BACKUP.name()))
                            .findFirst();

            assertTrue(backupMfa.isPresent());
            assertAll(
                    () -> assertEquals(SMS.name(), backupMfa.get().getMfaMethodType()),
                    () -> assertNull(backupMfa.get().getCredentialValue()),
                    () ->
                            assertEquals(
                                    backupSms.getDestination(), backupMfa.get().getDestination()));

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    CHANGED_DEFAULT_MFA,
                                    LocaleHelper.SupportedLanguage.EN)));
        }

        @Test
        void cannotChangeDefaultMethodToAuthAppWhenBackupIsAuthApp() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultSms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupAuthApp);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var updateRequest =
                    format(
                            UPDATE_MFA_TO_AUTH_APP_REQUEST_TEMPLATE,
                            "new-cred-AAAAAABBBBBCCCC",
                            notificationIdentifier.getValue());
            var mfaIdentifier = defaultSms.getMfaIdentifier();

            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(400, response.getStatusCode());
            assertThatJson(response.getBody()).node("code").isIntegralNumber().isEqualTo("1082");

            assertNoNotificationsReceived(notificationsQueue);
        }
    }

    @Nested
    class SwitchingMethods {
        public static final MFAMethodNotificationIdentifier notificationIdentifier =
                MFAMethodNotificationIdentifier.SWITCHED_MFA_METHODS;

        private void assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                MFAMethod expected, MFAMethod retrieved, PriorityIdentifier expectedPriority) {
            assertAll(
                    () -> assertEquals(expected.getMfaMethodType(), retrieved.getMfaMethodType()),
                    () -> assertEquals(expectedPriority.name(), retrieved.getPriority()),
                    () -> assertEquals(expected.getMfaIdentifier(), retrieved.getMfaIdentifier()),
                    () -> assertEquals(expected.isEnabled(), retrieved.isEnabled()),
                    () -> assertEquals(expected.isMethodVerified(), retrieved.isMethodVerified()),
                    () ->
                            assertEquals(
                                    expected.getCredentialValue(), retrieved.getCredentialValue()),
                    () -> assertEquals(expected.getDestination(), retrieved.getDestination()));
        }

        public static final String SMS_MFA_METHOD_TEMPLATE =
                """
                {
                     "mfaIdentifier":"%s",
                     "priorityIdentifier":"%s",
                     "methodVerified":true,
                     "method": {
                       "mfaMethodType":"SMS",
                       "phoneNumber":"%s"
                     }
                 }
                """;
        public static final String AUTH_APP_MFA_METHOD_TEMPLATE =
                """
                {
                     "mfaIdentifier":"%s",
                     "priorityIdentifier":"%s",
                     "methodVerified":true,
                     "method": {
                       "mfaMethodType":"AUTH_APP",
                       "credential":"%s"
                     }
                 }
                """;

        public static final String SWITCH_REQUEST =
                """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT"
                  },
                  "notificationIdentifier": "%s"
                }
                """;

        @Test
        void canSwitchBackupSMSToDefaultMethod() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultSms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupSms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var backupMfaIdentifier = backupSms.getMfaIdentifier();

            var response =
                    makeRequest(
                            Optional.of(format(SWITCH_REQUEST, notificationIdentifier.getValue())),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", backupMfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            var expectedDefault =
                    format(
                            SMS_MFA_METHOD_TEMPLATE,
                            backupMfaIdentifier,
                            DEFAULT,
                            backupSms.getDestination());

            var expectedBackup =
                    format(
                            SMS_MFA_METHOD_TEMPLATE,
                            defaultSms.getMfaIdentifier(),
                            BACKUP,
                            defaultSms.getDestination());

            assertThatJson(response.getBody())
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(format("[%s,%s]", expectedBackup, expectedDefault));

            var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            var retrievedDefault = getMethodWithPriority(retrievedMfaMethods, DEFAULT);
            var retrievedBackup = getMethodWithPriority(retrievedMfaMethods, BACKUP);

            assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                    backupSms, retrievedDefault, DEFAULT);
            assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                    defaultSms, retrievedBackup, BACKUP);

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    SWITCHED_MFA_METHODS,
                                    LocaleHelper.SupportedLanguage.EN)));
        }

        @Test
        void canSwitchBackupAuthAppToDefault() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultSms);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupAuthApp);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var backupMfaIdentifier = backupAuthApp.getMfaIdentifier();

            var response =
                    makeRequest(
                            Optional.of(format(SWITCH_REQUEST, notificationIdentifier.getValue())),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", backupMfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

            var expectedPromotedBackup =
                    format(
                            AUTH_APP_MFA_METHOD_TEMPLATE,
                            backupMfaIdentifier,
                            DEFAULT,
                            backupAuthApp.getCredentialValue());

            var expectedDemotedDefault =
                    format(
                            SMS_MFA_METHOD_TEMPLATE,
                            defaultSms.getMfaIdentifier(),
                            BACKUP,
                            defaultSms.getDestination());

            assertThatJson(response.getBody())
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(format("[%s,%s]", expectedDemotedDefault, expectedPromotedBackup));

            var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            var retrievedDefault = getMethodWithPriority(retrievedMfaMethods, DEFAULT);
            var retrievedBackup = getMethodWithPriority(retrievedMfaMethods, BACKUP);

            assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                    backupAuthApp, retrievedDefault, DEFAULT);
            assertRetrievedMethodHasSameFieldsWithUpdatedPriority(
                    defaultSms, retrievedBackup, BACKUP);

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    TEST_EMAIL,
                                    SWITCHED_MFA_METHODS,
                                    LocaleHelper.SupportedLanguage.EN)));
        }
    }

    @Nested
    class UserMigration {

        private void createUnMigratedUserWithIntermediateMfaIdentifier(String mfaIdentifier) {
            userStore.setPhoneNumberAndVerificationStatus(
                    TEST_EMAIL, TEST_PHONE_NUMBER, true, true);
            userStore.setPhoneNumberMfaIdentifer(TEST_EMAIL, mfaIdentifier);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, false);
        }

        @Test
        void shouldMigrateANonMigratedUserBeforePerformingAnyUpdates() {
            var mfaIdentifier = "mfaIdentifierForNonMigratedSms";
            createUnMigratedUserWithIntermediateMfaIdentifier(mfaIdentifier);

            var secondPhoneNumber = "+447900000100";
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);

            var updateRequest =
                    format(UPDATE_SMS_METHOD_REQUEST_TEMPLATE, secondPhoneNumber, otp, "");

            var response =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, response.getStatusCode());

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

            assertThatJson(response.getBody())
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(expectedResponseBody);

            var userProfileAfterUpdate = userStore.getUserProfileFromEmail(TEST_EMAIL);

            assertTrue(userProfileAfterUpdate.isPresent());

            assertAll(
                    () -> assertTrue(userProfileAfterUpdate.get().getMfaMethodsMigrated()),
                    () -> assertFalse(userProfileAfterUpdate.get().isPhoneNumberVerified()),
                    () -> assertNull(userProfileAfterUpdate.get().getPhoneNumber()));

            var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            assertEquals(1, retrievedMfaMethods.size());

            var retrievedMethod = retrievedMfaMethods.get(0);

            assertAll(
                    () -> assertEquals(SMS.getValue(), retrievedMethod.getMfaMethodType()),
                    () -> assertEquals(DEFAULT.name(), retrievedMethod.getPriority()),
                    () -> assertEquals(mfaIdentifier, retrievedMethod.getMfaIdentifier()),
                    () -> assertTrue(retrievedMethod.isEnabled()),
                    () -> assertTrue(retrievedMethod.isMethodVerified()),
                    () -> assertEquals(secondPhoneNumber, retrievedMethod.getDestination()));
        }
    }

    @Nested
    class Idempotence {

        @Test
        void duplicateUpdatesShouldBeIdempotentForUpdatesToDefaultMethod() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultAuthApp);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);
            var mfaIdentifier = defaultAuthApp.getMfaIdentifier();
            var updatedCredential = "some-new-credential";
            var updateRequest =
                    format(UPDATE_MFA_TO_AUTH_APP_REQUEST_TEMPLATE, updatedCredential, "");

            var firstResponse =
                    makeRequest(
                            Optional.of(updateRequest),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", mfaIdentifier)),
                            Map.of("principalId", testInternalSubject));

            assertEquals(200, firstResponse.getStatusCode());

            var retrievedMfaMethods = userStore.getMfaMethod(TEST_EMAIL);

            assertEquals(1, retrievedMfaMethods.size());

            var retrievedMethodAfterFirstRequest = retrievedMfaMethods.get(0);

            assertRetrievedMethodHasSameBasicFields(
                    defaultAuthApp, retrievedMethodAfterFirstRequest);
            assertMfaCredentialUpdated(retrievedMethodAfterFirstRequest, updatedCredential);

            for (int i = 0; i < 5; i++) {
                var response =
                        makeRequest(
                                Optional.of(updateRequest),
                                Collections.emptyMap(),
                                Collections.emptyMap(),
                                Map.ofEntries(
                                        Map.entry("publicSubjectId", testPublicSubject),
                                        Map.entry("mfaIdentifier", mfaIdentifier)),
                                Map.of("principalId", testInternalSubject));

                assertEquals(204, response.getStatusCode());

                var retrievedMethodsAfterSubsequentUpdates = userStore.getMfaMethod(TEST_EMAIL);

                assertEquals(1, retrievedMethodsAfterSubsequentUpdates.size());

                var retrievedMethod = retrievedMethodsAfterSubsequentUpdates.get(0);

                assertRetrievedMethodHasSameBasicFields(defaultAuthApp, retrievedMethod);
                assertEquals(
                        retrievedMethodAfterFirstRequest.getCredentialValue(),
                        retrievedMethod.getCredentialValue());
            }
        }
    }

    @Nested
    class ChangingBackupMethod {
        public static final MFAMethodNotificationIdentifier notificationIdentifier =
                MFAMethodNotificationIdentifier.SWITCHED_MFA_METHODS;

        private static String buildUpdateRequestWithOtp() {
            var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);
            return format(
                    UPDATE_SMS_METHOD_REQUEST_TEMPLATE,
                    backupSms.getDestination(),
                    otp,
                    notificationIdentifier.getValue());
        }

        @Test
        void cannotEditBackupMethod() {
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultAuthApp);
            userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupSms);
            userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

            var mfaIdentifierOfBackup = backupSms.getMfaIdentifier();
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
                    defaultAuthApp, getMethodWithPriority(retrievedMfaMethods, DEFAULT));

            assertRetrievedMethodHasSameBasicFields(
                    backupSms, getMethodWithPriority(retrievedMfaMethods, BACKUP));

            assertNoNotificationsReceived(notificationsQueue);
        }
    }

    @Nested
    class Validations {

        @Test
        void shouldReturn401WhenPrincipalIsInvalid() {
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", testPublicSubject),
                                    Map.entry("mfaIdentifier", "mfaIdentifier")),
                            Map.of("principalId", "invalid-internal-subject-id"));

            assertEquals(401, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1079));

            assertNoNotificationsReceived(notificationsQueue);
        }

        @Test
        void shouldReturn404WhenUserProfileIsNotFoundForPublicSubject() {
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", "invalid-public-subject-id"),
                                    Map.entry("mfaIdentifier", "mfa-identifier")),
                            Map.of("principalId", testInternalSubject));

            assertEquals(404, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));

            assertNoNotificationsReceived(notificationsQueue);
        }
    }
}
