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
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthenticateIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new AuthenticateHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() throws Exception {
        String email = buildTestEmail(3);
        userStore.signUp(email, PASSWORD);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, PASSWORD)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(ACCOUNT_MANAGEMENT_AUTHENTICATE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials() {
        String email = buildTestEmail(4);
        userStore.signUp(email, PASSWORD_BAD);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, PASSWORD)), Map.of(), Map.of());

        assertThat(response, hasStatus(401));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE));
    }
}
