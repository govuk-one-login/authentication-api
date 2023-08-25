package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationAuthCodeHandlerTest {
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_REDIRECT_URI = "https://redirect_uri.com";
    private static final String TEST_STATE = "xyz";
    private static final String TEST_AUTHORIZATION_CODE = "SplxlOBeZQQYbYS6WxSbIA";
    private static final String TEST_SUBJECT_ID = "subject-id";

    private AuthenticationAuthCodeHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();
    private final Context context = mock(Context.class);
    private final DynamoAuthCodeService dynamoAuthCodeService = mock(DynamoAuthCodeService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final Session session =
            new Session(IdGenerator.generate()).setEmailAddress(TEST_EMAIL_ADDRESS);

    @BeforeEach
    void setUp() throws Json.JsonException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        UserProfile userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        handler =
                new AuthenticationAuthCodeHandler(
                        dynamoAuthCodeService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService);
    }

    @Test
    void shouldReturn500ErrorWhenAuthenticationAuthCodeHandlerIsDisabled()
            throws Json.JsonException {
        when(configurationService.isAuthOrchSplitEnabled()).thenReturn(false);
        var event = validAuthCodeRequest();
        event.setHeaders(getHeaders());

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(500));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1050)));
    }

    @Test
    void shouldReturn400ErrorWhenEmailIsInvalid() throws Json.JsonException {
        when(configurationService.isAuthOrchSplitEnabled()).thenReturn(true);
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\"}", ""));

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenRedirectUriIsInvalid() throws Json.JsonException {
        when(configurationService.isAuthOrchSplitEnabled()).thenReturn(true);
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(
                format("{ \"email\": \"%s\", \"redirect-uri\": \"%s\" }", TEST_EMAIL_ADDRESS, ""));

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenStateIsInvalid() throws Json.JsonException {
        when(configurationService.isAuthOrchSplitEnabled()).thenReturn(true);
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, TEST_REDIRECT_URI, ""));

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenUnableToFetchEmailFromUserProfile() throws Json.JsonException {
        when(configurationService.isAuthOrchSplitEnabled()).thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());
        var event = validAuthCodeRequest();

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1049)));
    }

    @Test
    void shouldReturn200AndSaveNewAuthCodeRequest() throws Json.JsonException {
        when(configurationService.isAuthOrchSplitEnabled()).thenReturn(true);
        when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
        var userProfile = new UserProfile();
        userProfile.setSubjectID(TEST_SUBJECT_ID);
        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        var event = validAuthCodeRequest();

        var result = handler.handleRequest(event, context);

        verify(dynamoAuthCodeService, times(1))
                .saveAuthCode(eq(userProfile.getSubjectID()), anyString(), anyList(), eq(false));
        assertThat(result, hasStatus(200));
        var authorizationResponse = new AuthCodeResponse(TEST_AUTHORIZATION_CODE, TEST_STATE);
        assertThat(result, hasBody(objectMapper.writeValueAsString(authorizationResponse)));
    }

    private APIGatewayProxyRequestEvent validAuthCodeRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"] }",
                        TEST_EMAIL_ADDRESS,
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email")));
        return event;
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", session.getSessionId());
        return headers;
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(TEST_EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }
}
