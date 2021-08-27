package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.NotifyRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class MfaHandlerTest {

    private MfaHandler handler;
    private static final String PHONE_NUMBER = "01234567890";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final Session session =
            new Session("a-session-id")
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setState(SessionState.LOGGED_IN);

    @BeforeEach
    public void setUp() {
        handler =
                new MfaHandler(
                        configurationService,
                        sessionService,
                        codeGeneratorService,
                        codeStorageService,
                        authenticationService,
                        sqsClient);
    }

    @Test
    public void shouldReturn200ForSuccessfulMfaRequest() throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(PHONE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        NotifyRequest notifyRequest = new NotifyRequest(PHONE_NUMBER, MFA_SMS, CODE);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(TEST_EMAIL_ADDRESS, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn400WhenSessionIdIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    public void shouldReturnErrorResponseWhenUsersPhoneNumberIsNotStored() {
        usingValidSession();
        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS)).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1014));
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongState() throws JsonProcessingException {
        session.setState(SessionState.NEW);

        usingValidSession();

        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(PHONE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verifyNoInteractions(sqsClient, codeStorageService);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }
}
