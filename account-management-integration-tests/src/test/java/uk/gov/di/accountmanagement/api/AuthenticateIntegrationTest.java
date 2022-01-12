package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.accountmanagement.lambda.AuthenticateHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Map;
import java.util.Optional;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.AuditEventMatcher.hasEventType;

public class AuthenticateIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new AuthenticateHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, password);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        await().atMost(10, SECONDS)
                .untilAsserted(() -> assertThat(auditTopic.getCountOfRequests(), equalTo(1)));
        assertThat(
                auditTopic.getAuditEvents(),
                hasItem(
                        hasEventType(
                                AccountManagementAuditableEvent.class,
                                ACCOUNT_MANAGEMENT_AUTHENTICATE)));
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
    }
}
