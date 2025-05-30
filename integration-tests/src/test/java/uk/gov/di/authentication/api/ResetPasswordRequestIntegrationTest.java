package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasLength;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordRequestIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "some-client-name";

    @BeforeEach
    public void setUp() {
        handler =
                new ResetPasswordRequestHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200ForCodeFlowRequest() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addVerifiedPhoneNumber(email, phoneNumber);
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, email);
        String persistentSessionId = "test-persistent-id";
        var clientSessionId = IdGenerator.generate();
        registerClient(email, CLIENT_ID, CLIENT_NAME, REDIRECT_URI);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email)),
                        constructFrontendHeaders(sessionId, clientSessionId, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(email));
        assertThat(requests.get(0).getNotificationType(), equalTo(RESET_PASSWORD_WITH_CODE));
        assertThat(requests.get(0).getCode(), hasLength(6));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, Collections.singletonList(AUTH_PASSWORD_RESET_REQUESTED));
    }
}
