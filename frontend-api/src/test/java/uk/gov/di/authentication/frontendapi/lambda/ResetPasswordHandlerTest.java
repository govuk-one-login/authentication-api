package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ResetPasswordHandlerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final Context context = mock(Context.class);
    private static final String CODE = "12345678901";
    private static final String NEW_PASSWORD = "Pa55word!";
    private static final String SUBJECT = "some-subject";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private ResetPasswordHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new ResetPasswordHandler(
                        authenticationService, sqsClient, codeStorageService, validationService);
    }

    @Test
    public void shouldReturn200ForSuccessfulRequest() throws JsonProcessingException {
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials());
        NotifyRequest notifyRequest =
                new NotifyRequest(EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(sqsClient, times(1)).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);
    }

    @Test
    public void shouldReturn400ForRequestIsMissingParameters() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\"}", CODE));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfPasswordFailsValidation() {
        String invalidPassword = "password";
        when(validationService.validatePassword(invalidPassword))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1007));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, "password"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1007));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
    }

    @Test
    public void shouldReturn400WhenCodeIsInvalid() {
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE)).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1021));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
    }

    private UserCredentials generateUserCredentials() {
        return new UserCredentials()
                .setEmail(EMAIL)
                .setPassword("old-password1")
                .setSubjectID(SUBJECT);
    }
}
