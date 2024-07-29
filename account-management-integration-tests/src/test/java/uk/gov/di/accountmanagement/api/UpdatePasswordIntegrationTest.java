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
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.UPDATE_PASSWORD;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSWORD_UPDATED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdatePasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler = new UpdatePasswordHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldSendNotificationAndReturn204WhenUpdatingPasswordIsSuccessful() {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId(PASSWORD);
        var hashedOriginalPassword = userStore.getPasswordForUser(EMAIL);

        Map<String, Object> requestParams =
                Map.of("principalId", internalCommonSubId, "clientId", CLIENT_ID);
        var response =
                makeRequest(
                        Optional.of(new UpdatePasswordRequest(EMAIL, PASSWORD_NEW)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        requestParams);

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));
        assertThat(userStore.getPasswordForUser(EMAIL), not(is(hashedOriginalPassword)));

        assertNotificationsReceived(
                notificationsQueue,
                List.of(new NotifyRequest(EMAIL, PASSWORD_UPDATED, SupportedLanguage.EN)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(txmaAuditQueue, List.of(UPDATE_PASSWORD));
    }

    @Test
    void shouldReturn400WhenNewPasswordIsSameAsOldPassword() throws Exception {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId(PASSWORD);

        var response =
                makeRequest(
                        Optional.of(new UpdatePasswordRequest(EMAIL, PASSWORD)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", internalCommonSubId));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1024)));

        assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldReturn400WhenNewPasswordIsInvalid() throws Exception {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId(PASSWORD);

        Map<String, Object> requestParams =
                Map.of("principalId", internalCommonSubId, "clientId", CLIENT_ID);

        var response =
                makeRequest(
                        Optional.of(
                                new UpdatePasswordRequest(
                                        EMAIL, CommonPasswordsExtension.TEST_COMMON_PASSWORD)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        requestParams);

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1040)));

        assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldThrowExceptionWhenUserAttemptsToUpdateDifferentAccount() {
        var internalCommonSubId = setupUserAndRetrieveInternalCommonSubId(PASSWORD);
        var OTHER_EMAIL = buildTestEmail("other");
        userStore.signUp(OTHER_EMAIL, PASSWORD_NEW, new Subject());

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePasswordRequest(
                                                        OTHER_EMAIL, PASSWORD_NEW)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Map.of("principalId", internalCommonSubId)));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    @Test
    void shouldThrowExceptionWhenSubjectIdMissing() {
        setupUserAndRetrieveInternalCommonSubId(PASSWORD);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(new UpdatePasswordRequest(EMAIL, PASSWORD)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap()));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    @SuppressWarnings("SameParameterValue")
    private String setupUserAndRetrieveInternalCommonSubId(String password) {
        userStore.signUp(EMAIL, password, SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        return internalCommonSubjectId;
    }
}
