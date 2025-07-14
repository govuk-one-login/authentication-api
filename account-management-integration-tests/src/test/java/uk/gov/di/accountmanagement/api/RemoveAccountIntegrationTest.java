package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.RemoveAccountRequest;
import uk.gov.di.accountmanagement.lambda.RemoveAccountHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_DELETE_ACCOUNT;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class RemoveAccountIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";

    @BeforeEach
    void setup() {
        handler = new RemoveAccountHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
        notificationsQueue.clear();
    }

    @Test
    void shouldRemoveAccountAndAccountModifiersEntryAndReturn204WhenUserExists() {
        var internalCommonSubjectId = setupUserAndRetrieveInternalCommonSubId();
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);

        var response =
                makeRequest(
                        Optional.of(new RemoveAccountRequest(EMAIL)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", internalCommonSubjectId));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        assertFalse(userStore.userExists(EMAIL));
        assertFalse(accountModifiersStore.isEntryForSubjectIdPresent(internalCommonSubjectId));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_DELETE_ACCOUNT));
    }

    @Test
    void shouldRemoveAccountAndReturn204WhenUserExists() {
        var internalCommonSubjectId = setupUserAndRetrieveInternalCommonSubId();

        var response =
                makeRequest(
                        Optional.of(new RemoveAccountRequest(EMAIL)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", internalCommonSubjectId));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        assertFalse(userStore.userExists(EMAIL));
        assertFalse(accountModifiersStore.isEntryForSubjectIdPresent(internalCommonSubjectId));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_DELETE_ACCOUNT));
    }

    @Test
    void shouldThrowExceptionWhenUserAttemptsToDeleteDifferentAccount() {
        String user2Email = "i-do-not-exist@example.com";
        String password2 = "password-2";
        Subject subject2 = new Subject();

        var subjectId1 = setupUserAndRetrieveInternalCommonSubId();
        userStore.signUp(user2Email, password2, subject2);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(new RemoveAccountRequest(user2Email)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Map.of("principalId", subjectId1)));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    @Test
    void shouldReturn400WhenAttemptingToDeleteNonexistentUser() throws Json.JsonException {
        String email = "i.do.not.exist@digital.cabinet-office.gov.uk";

        var response =
                makeRequest(
                        Optional.of(new RemoveAccountRequest(email)),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsString(ErrorResponse.ACCT_DOES_NOT_EXIST)));

        assertNoNotificationsReceived(notificationsQueue);
        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    private String setupUserAndRetrieveInternalCommonSubId() {
        userStore.signUp(EMAIL, "password-1", SUBJECT);
        byte[] salt = userStore.addSalt(EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        return internalCommonSubjectId;
    }
}
