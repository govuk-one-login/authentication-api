package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.lambda.MFAMethodsDeleteHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Map.entry;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_DELETE_COMPLETED;
import static uk.gov.di.accountmanagement.entity.NotificationType.BACKUP_METHOD_REMOVED;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_MFA_TYPE;
import static uk.gov.di.accountmanagement.testsupport.AuditTestConstants.EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsDeleteHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String PASSWORD = "password-1";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static String testInternalSubject;
    private static final MFAMethod DEFAULT_AUTH_APP =
            MFAMethod.authAppMfaMethod(
                    "some-credential", true, true, DEFAULT, "a44aa7a9-463a-4e10-93dd-bde8de3215bc");
    private static final MFAMethod BACKUP_SMS =
            MFAMethod.smsMfaMethod(
                    true, true, "07700900000", BACKUP, "20fbea7e-4c4e-4a32-a7b5-000bb4863660");
    private static final MFAMethod DEFAULT_SMS =
            MFAMethod.smsMfaMethod(
                    true, true, "07700900001", DEFAULT, "30fbea7e-4c4e-4a32-a7b5-000bb4863661");
    private static final MFAMethod BACKUP_AUTH_APP =
            MFAMethod.authAppMfaMethod(
                    "backup-credential",
                    true,
                    true,
                    BACKUP,
                    "b44aa7a9-463a-4e10-93dd-bde8de3215bd");
    private static final MFAMethod BACKUP_SMS_2 =
            MFAMethod.smsMfaMethod(
                    true, true, "07700900002", BACKUP, "40fbea7e-4c4e-4a32-a7b5-000bb4863662");
    private String publicSubjectId;

    @BeforeEach
    void setUp() {
        handler = new MFAMethodsDeleteHandler(ACCOUNT_MANAGEMENT_TXMA_ENABLED_CONFIGUARION_SERVICE);
        publicSubjectId = userStore.signUp(EMAIL, PASSWORD);
        byte[] salt = userStore.addSalt(EMAIL);
        testInternalSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userStore.getUserProfileFromEmail(EMAIL).get().getSubjectID(),
                        INTERNAL_SECTOR_HOST,
                        salt);

        notificationsQueue.clear();
    }

    @Nested
    class SuccessfulDelete {
        static Stream<Arguments> mfaMethodCombinations() {
            return Stream.of(
                    Arguments.of(DEFAULT_AUTH_APP, BACKUP_SMS, AUTH_APP),
                    Arguments.of(DEFAULT_SMS, BACKUP_AUTH_APP, SMS),
                    Arguments.of(DEFAULT_SMS, BACKUP_SMS_2, SMS));
        }

        @ParameterizedTest
        @MethodSource("mfaMethodCombinations")
        void shouldReturn204AndDeleteAnMfaMethodWhenUserExists(
                MFAMethod defaultMethod,
                MFAMethod backupMethod,
                MFAMethodType expectedRemainingMethodType) {
            userStore.addMfaMethodSupportingMultiple(EMAIL, defaultMethod);
            userStore.addMfaMethodSupportingMultiple(EMAIL, backupMethod);
            userStore.setMfaMethodsMigrated(EMAIL, true);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.empty(),
                            headers,
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", publicSubjectId),
                                    entry("mfaIdentifier", backupMethod.getMfaIdentifier())),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(204, response.getStatusCode());

            var mfaMethods = userStore.getMfaMethod(EMAIL);
            assertEquals(1, mfaMethods.size());

            var mfaMethodOptional = mfaMethods.stream().findFirst();
            assertTrue(mfaMethodOptional.isPresent());
            var mfaMethod = mfaMethodOptional.get();

            assertEquals(expectedRemainingMethodType.getValue(), mfaMethod.getMfaMethodType());
            assertEquals(defaultMethod.getMfaIdentifier(), mfaMethod.getMfaIdentifier());

            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(
                            new NotifyRequest(
                                    EMAIL,
                                    BACKUP_METHOD_REMOVED,
                                    LocaleHelper.SupportedLanguage.EN)));

            List<AuditableEvent> expectedEvents = List.of(AUTH_MFA_METHOD_DELETE_COMPLETED);

            var sentEvents = assertTxmaAuditEventsReceived(txmaAuditQueue, expectedEvents);

            AuditEventExpectation expectation =
                    new AuditEventExpectation(AUTH_MFA_METHOD_DELETE_COMPLETED);
            expectation.withAttribute(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());

            // Only add phone number country code for SMS methods
            if (backupMethod.getMfaMethodType().equals(MFAMethodType.SMS.getValue())) {
                expectation.withAttribute(EXTENSIONS_MFA_TYPE, SMS.getValue());
                expectation.withAttribute(EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE, "44");
            } else if (backupMethod.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue())) {
                expectation.withAttribute(EXTENSIONS_MFA_TYPE, AUTH_APP.getValue());
            }

            expectation.assertPublished(sentEvents);
        }

        @Test
        void userDeletesAuthenticatorAppBackupMethod() {
            userStore.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_SMS);
            userStore.addMfaMethodSupportingMultiple(EMAIL, BACKUP_AUTH_APP);
            userStore.setMfaMethodsMigrated(EMAIL, true);

            Map<String, String> headers = new HashMap<>();
            headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS");

            var response =
                    makeRequest(
                            Optional.empty(),
                            headers,
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", publicSubjectId),
                                    entry("mfaIdentifier", BACKUP_AUTH_APP.getMfaIdentifier())),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(204, response.getStatusCode());

            List<AuditableEvent> expectedEvents = List.of(AUTH_MFA_METHOD_DELETE_COMPLETED);
            var sentEvents = assertTxmaAuditEventsReceived(txmaAuditQueue, expectedEvents);

            AuditEventExpectation expectation =
                    new AuditEventExpectation(AUTH_MFA_METHOD_DELETE_COMPLETED);
            expectation.withAttribute(EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.name());
            expectation.withAttribute(EXTENSIONS_MFA_TYPE, AUTH_APP.getValue());

            expectation.assertPublished(sentEvents);
        }
    }

    @Nested
    class ClientError {
        @Test
        void shouldReturn404WhenUserDoesNotExist() {
            var nonExistentPublicSubjectId = "userDoesNotExist";
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", nonExistentPublicSubjectId),
                                    entry("mfaIdentifier", "mfaIdentifier")),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(404, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

            assertNoNotificationsReceived(notificationsQueue);
        }

        @Test
        void shouldReturn404WhenMfaMethodDoesNotExist() {
            userStore.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_AUTH_APP);
            userStore.addMfaMethodSupportingMultiple(EMAIL, BACKUP_SMS);
            userStore.setMfaMethodsMigrated(EMAIL, true);
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", publicSubjectId),
                                    entry("mfaIdentifier", "some-other-identifier")),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(404, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.MFA_METHOD_NOT_FOUND));

            assertEquals(2, userStore.getMfaMethod(EMAIL).size());

            assertNoNotificationsReceived(notificationsQueue);
        }

        @Test
        void shouldReturn400WhenMfaMethodIsDefault() {
            userStore.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_AUTH_APP);
            userStore.addMfaMethodSupportingMultiple(EMAIL, BACKUP_SMS);
            userStore.setMfaMethodsMigrated(EMAIL, true);
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", publicSubjectId),
                                    entry("mfaIdentifier", DEFAULT_AUTH_APP.getMfaIdentifier())),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(409, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.CANNOT_DELETE_DEFAULT_MFA));

            assertEquals(2, userStore.getMfaMethod(EMAIL).size());

            assertNoNotificationsReceived(notificationsQueue);
        }

        @Test
        void shouldReturn400WhenUsersMfaMethodsAreNotMigrated() {
            userStore.setMfaMethodsMigrated(EMAIL, false);

            userStore.addMfaMethod(EMAIL, MFAMethodType.AUTH_APP, true, true, "credential");
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", publicSubjectId),
                                    entry("mfaIdentifier", DEFAULT_AUTH_APP.getMfaIdentifier())),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(400, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.CANNOT_DELETE_MFA_FOR_UNMIGRATED_USER));

            assertEquals(1, userStore.getMfaMethod(EMAIL).size());

            assertNoNotificationsReceived(notificationsQueue);
        }

        @Test
        void shouldReturn401WhenPrincipalIsInvalid() {
            var response =
                    makeRequest(
                            Optional.empty(),
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.ofEntries(
                                    entry("publicSubjectId", publicSubjectId),
                                    entry("mfaIdentifier", DEFAULT_AUTH_APP.getMfaIdentifier())),
                            Map.ofEntries(entry("principalId", "invalid-principal")));

            assertEquals(401, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_PRINCIPAL));

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
                                    entry("publicSubjectId", "invalid-public-subject-id"),
                                    entry("mfaIdentifier", DEFAULT_AUTH_APP.getMfaIdentifier())),
                            Map.ofEntries(entry("principalId", testInternalSubject)));

            assertEquals(404, response.getStatusCode());
            assertThat(response, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

            assertNoNotificationsReceived(notificationsQueue);
        }
    }
}
