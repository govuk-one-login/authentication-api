package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.lambda.MFAMethodsDeleteHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.accountmanagement.entity.NotificationType.BACKUP_METHOD_REMOVED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsDeleteHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String PASSWORD = "password-1";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static String testInternalSubject;
    private static final MFAMethod DEFAULT_PRIORITY_AUTH_APP =
            MFAMethod.authAppMfaMethod(
                    "some-credential",
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    "a44aa7a9-463a-4e10-93dd-bde8de3215bc");
    private static final MFAMethod BACKUP_PRIORITY_SMS =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    "0123456",
                    PriorityIdentifier.BACKUP,
                    "20fbea7e-4c4e-4a32-a7b5-000bb4863660");
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

    @Test
    void shouldReturn204AndDeleteAnMfaMethodWhenUserExists() {
        userStore.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_PRIORITY_AUTH_APP);
        userStore.addMfaMethodSupportingMultiple(EMAIL, BACKUP_PRIORITY_SMS);
        userStore.setMfaMethodsMigrated(EMAIL, true);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                BACKUP_PRIORITY_SMS.getMfaIdentifier()),
                        Map.of("principalId", testInternalSubject));

        assertEquals(204, response.getStatusCode());

        var mfaMethods = userStore.getMfaMethod(EMAIL);
        assertEquals(1, mfaMethods.size());

        var mfaMethod = mfaMethods.stream().findFirst().get();

        assertEquals(MFAMethodType.AUTH_APP.getValue(), mfaMethod.getMfaMethodType());
        assertEquals(DEFAULT_PRIORITY_AUTH_APP.getMfaIdentifier(), mfaMethod.getMfaIdentifier());

        assertNotificationsReceived(
                notificationsQueue,
                List.of(
                        new NotifyRequest(
                                EMAIL, BACKUP_METHOD_REMOVED, LocaleHelper.SupportedLanguage.EN)));
    }

    @Test
    void shouldReturn404WhenUserDoesNotExist() {
        var nonExistentPublicSubjectId = "userDoesNotExist";
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                nonExistentPublicSubjectId,
                                "mfaIdentifier",
                                "mfaIdentifier"),
                        Map.of("principalId", testInternalSubject));

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));

        assertNoNotificationsReceived(notificationsQueue);
    }

    @Test
    void shouldReturn404WhenMfaMethodDoesNotExist() {
        userStore.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_PRIORITY_AUTH_APP);
        userStore.addMfaMethodSupportingMultiple(EMAIL, BACKUP_PRIORITY_SMS);
        userStore.setMfaMethodsMigrated(EMAIL, true);
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                "some-other-identifier"),
                        Map.of("principalId", testInternalSubject));

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1065));

        assertEquals(2, userStore.getMfaMethod(EMAIL).size());

        assertNoNotificationsReceived(notificationsQueue);
    }

    @Test
    void shouldReturn400WhenMfaMethodIsDefault() {
        userStore.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_PRIORITY_AUTH_APP);
        userStore.addMfaMethodSupportingMultiple(EMAIL, BACKUP_PRIORITY_SMS);
        userStore.setMfaMethodsMigrated(EMAIL, true);
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                DEFAULT_PRIORITY_AUTH_APP.getMfaIdentifier()),
                        Map.of("principalId", testInternalSubject));

        assertEquals(409, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1066));

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
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                DEFAULT_PRIORITY_AUTH_APP.getMfaIdentifier()),
                        Map.of("principalId", testInternalSubject));

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1067));

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
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                DEFAULT_PRIORITY_AUTH_APP.getMfaIdentifier()),
                        Map.of("principalId", "invalid-principal"));

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
                        Map.of(
                                "publicSubjectId",
                                "invalid-public-subject-id",
                                "mfaIdentifier",
                                DEFAULT_PRIORITY_AUTH_APP.getMfaIdentifier()),
                        Map.of("principalId", testInternalSubject));

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));

        assertNoNotificationsReceived(notificationsQueue);
    }
}
