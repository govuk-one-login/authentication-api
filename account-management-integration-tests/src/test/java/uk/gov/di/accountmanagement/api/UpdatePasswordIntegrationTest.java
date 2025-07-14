package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePasswordRequest;
import uk.gov.di.accountmanagement.lambda.UpdatePasswordHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.CommonPasswordsExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PASSWORD;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSWORD_UPDATED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdatePasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final String CLIENT_ID = "some-client-id";

    @BeforeEach
    void setup() {
        handler = new UpdatePasswordHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldSendNotificationAndReturn204WhenUpdatingPasswordIsSuccessful() {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId("password-1");
        var hashedOriginalPassword = userStore.getPasswordForUser(TEST_EMAIL);

        Map<String, Object> requestParams =
                Map.of("principalId", internalCommonSubId, "clientId", CLIENT_ID);
        var response =
                makeRequest(
                        Optional.of(new UpdatePasswordRequest(TEST_EMAIL, "password-2")),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        requestParams);

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));
        assertThat(userStore.getPasswordForUser(TEST_EMAIL), not(is(hashedOriginalPassword)));

        assertNotificationsReceived(
                notificationsQueue,
                List.of(new NotifyRequest(TEST_EMAIL, PASSWORD_UPDATED, SupportedLanguage.EN)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_UPDATE_PASSWORD));
    }

    @Test
    void shouldReturn400WhenNewPasswordIsSameAsOldPassword() throws Exception {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId("password-1");

        var response =
                makeRequest(
                        Optional.of(new UpdatePasswordRequest(TEST_EMAIL, "password-1")),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", internalCommonSubId));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsString(ErrorResponse.NEW_PW_MATCHES_OLD)));

        assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldReturn400WhenNewPasswordIsInvalid() throws Exception {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId("password-1");

        Map<String, Object> requestParams =
                Map.of("principalId", internalCommonSubId, "clientId", CLIENT_ID);

        var response =
                makeRequest(
                        Optional.of(
                                new UpdatePasswordRequest(
                                        TEST_EMAIL, CommonPasswordsExtension.TEST_COMMON_PASSWORD)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        requestParams);

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.PW_TOO_COMMON)));

        assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldThrowExceptionWhenUserAttemptsToUpdateDifferentAccount() {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId("password-1");
        userStore.signUp("other.user@digital.cabinet-office.gov.uk", "password-2", new Subject());

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePasswordRequest(
                                                        "other.user@digital.cabinet-office.gov.uk",
                                                        "password-2")),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Map.of("principalId", internalCommonSubId)));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    @Test
    void shouldThrowExceptionWhenSubjectIdMissing() {
        setupUserAndRetrieveInternalCommonSubId("password-1");

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePasswordRequest(
                                                        TEST_EMAIL, "password-1")),
                                        Collections.emptyMap(),
                                        Collections.emptyMap()));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    private String setupUserAndRetrieveInternalCommonSubId(String password) {
        userStore.signUp(TEST_EMAIL, password, SUBJECT);
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        return internalCommonSubjectId;
    }
}
