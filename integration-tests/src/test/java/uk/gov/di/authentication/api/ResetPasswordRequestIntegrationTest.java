package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasLength;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.*;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordRequestIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID(CommonTestVariables.CLIENT_ID);

    @BeforeEach
    public void setUp() {
        handler =
                new ResetPasswordRequestHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200ForCodeFlowRequest()
            throws Json.JsonException {
        userStore.signUp(EMAIL, PASSWORD);
        userStore.addVerifiedPhoneNumber(EMAIL, UK_LANDLINE_NUMBER_NO_CC);
        String sessionId = redis.createSession();
        String persistentSessionId = "test-persistent-id";
        redis.addEmailToSession(sessionId, EMAIL);
        var clientSessionId = IdGenerator.generate();
        setUpClientSession(EMAIL, clientSessionId, CLIENT_ID, CLIENT_NAME, REDIRECT_URI);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(EMAIL)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL));
        assertThat(requests.get(0).getNotificationType(), equalTo(RESET_PASSWORD_WITH_CODE));
        assertThat(requests.get(0).getCode(), hasLength(6));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, Collections.singletonList(PASSWORD_RESET_REQUESTED));
    }
}
