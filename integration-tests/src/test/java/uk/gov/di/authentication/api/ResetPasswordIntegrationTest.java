package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PASSWORD = "Pa55word";
    private static final String CODE = "0123456789";

    @BeforeEach
    public void setUp() {
        handler = new ResetPasswordHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldUpdatePasswordAndReturn204() throws IOException {
        String subject = "new-subject";
        String sessionId = redis.createSession();
        userStore.signUp(EMAIL_ADDRESS, "password-1", new Subject(subject));
        redis.generateAndSavePasswordResetCode(subject, CODE, 900l);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordWithCodeRequest(CODE, PASSWORD)),
                        constructFrontendHeaders(sessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(EMAIL_ADDRESS));
        assertThat(requests.get(0).getNotificationType(), equalTo(PASSWORD_RESET_CONFIRMATION));
    }
}
