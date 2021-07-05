package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.VerifyCodeResponse;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeRequestHandlerTest {

    private static final Session SESSION =
            new Session("session-id").setEmailAddress("test@test.com");
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private VerifyCodeHandler handler;

    @BeforeEach
    public void setup() {
        handler = new VerifyCodeHandler(sessionService, configService, codeStorageService);
    }

    @Test
    public void shouldReturn200ForValidVerifyEmailRequest() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format("{ \"code\": \"123456\", \"notificationType\": \"%s\" }", VERIFY_EMAIL));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(SESSION));
        when(codeStorageService.getCodeForEmail("test@test.com")).thenReturn(Optional.of("123456"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        verify(codeStorageService).deleteCodeForEmail("test@test.com");
        assertThat(result, hasStatus(200));
        VerifyCodeResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), VerifyCodeResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_VERIFIED));
    }

    @Test
    public void shouldReturn200ForValidVerifyPhoneNumberRequest() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format(
                        "{ \"code\": \"123456\", \"notificationType\": \"%s\" }",
                        VERIFY_PHONE_NUMBER));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(SESSION));
        when(codeStorageService.getPhoneNumberCode("test@test.com"))
                .thenReturn(Optional.of("123456"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        verify(codeStorageService).deletePhoneNumberCode("test@test.com");
        assertThat(result, hasStatus(200));
        VerifyCodeResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), VerifyCodeResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_VERIFIED));
    }

    @Test
    public void shouldReturnEmailCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format("{ \"code\": \"123456\", \"notificationType\": \"%s\" }", VERIFY_EMAIL));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(SESSION));
        when(codeStorageService.getCodeForEmail("test@test.com")).thenReturn(Optional.of("654321"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        VerifyCodeResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), VerifyCodeResponse.class);

        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_NOT_VALID));
    }

    @Test
    public void shouldReturnPhoneNumberCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format(
                        "{ \"code\": \"123456\", \"notificationType\": \"%s\" }",
                        VERIFY_PHONE_NUMBER));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(SESSION));
        when(codeStorageService.getPhoneNumberCode("test@test.com"))
                .thenReturn(Optional.of("654321"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        VerifyCodeResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), VerifyCodeResponse.class);

        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_NOT_VALID));
    }

    @Test
    public void shouldReturn400IfRequestIsMissingNotificationType() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"code\": \"123456\"}"));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(SESSION));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));

        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfSessionIdIsInvalid() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format("{ \"code\": \"123456\", \"notificationType\": \"%s\" }", VERIFY_EMAIL));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfNotificationTypeIsNotValid() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format("{ \"code\": \"123456\", \"notificationType\": \"%s\" }", "VERIFY_TEXT"));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(SESSION));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(expectedResponse));
    }
}
