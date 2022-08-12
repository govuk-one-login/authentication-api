package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckUserExistsHandler;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CHECK_USER_NO_ACCOUNT_WITH_EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceivedByBothServices;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserExistsIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new CheckUserExistsHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    public void shouldCallUserExistsEndpointAndReturnAuthenticationRequestStateWhenUserExists()
            throws JsonException {
        String emailAddress = "joe.bloggs+1@digital.cabinet-office.gov.uk";
        String sessionId = redis.createSession();
        userStore.signUp(emailAddress, "password-1");

        CheckUserExistsRequest request = new CheckUserExistsRequest(emailAddress);

        var response =
                makeRequest(Optional.of(request), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(200));
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.getEmail(), equalTo(emailAddress));
        assertTrue(checkUserExistsResponse.doesUserExist());

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, List.of(CHECK_USER_KNOWN_EMAIL));
    }

    @Test
    public void shouldCallUserExistsEndpointAndReturnUserNotFoundStateWhenUserDoesNotExist()
            throws JsonException {
        String emailAddress = "joe.bloggs+2@digital.cabinet-office.gov.uk";
        String sessionId = redis.createSession();
        BaseFrontendRequest request = new CheckUserExistsRequest(emailAddress);

        var response =
                makeRequest(Optional.of(request), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(200));

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.getEmail(), equalTo(emailAddress));
        assertFalse(checkUserExistsResponse.doesUserExist());

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, List.of(CHECK_USER_NO_ACCOUNT_WITH_EMAIL));
    }
}
