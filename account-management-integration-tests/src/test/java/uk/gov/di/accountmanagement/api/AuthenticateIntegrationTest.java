package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.accountmanagement.lambda.AuthenticateHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceivedByBothServices;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceivedByEitherService;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthenticateIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new AuthenticateHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() throws Exception {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, password);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, List.of(ACCOUNT_MANAGEMENT_AUTHENTICATE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials() {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(401));

        assertNoAuditEventsReceivedByEitherService(auditTopic, txmaAuditQueue);
    }
}
