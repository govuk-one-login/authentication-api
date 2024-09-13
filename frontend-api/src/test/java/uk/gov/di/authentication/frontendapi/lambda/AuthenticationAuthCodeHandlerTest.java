package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationAuthCodeHandlerTest {
    private static final String TEST_REDIRECT_URI = "https://redirect_uri.com";
    private static final String TEST_STATE = "xyz";
    private static final String LOCATION = "location";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String TEST_SECTOR_IDENTIFIER = "sectorIdentifier";
    private static final Long PASSWORD_RESET_TIME = 1696869005821L;

    private AuthenticationAuthCodeHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();
    private final Context context = mock(Context.class);
    private final DynamoAuthCodeService dynamoAuthCodeService = mock(DynamoAuthCodeService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final Session session =
            new Session(SESSION_ID).setEmailAddress(CommonTestVariables.EMAIL);

    @BeforeEach
    void setUp() throws Json.JsonException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        UserProfile userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));
        handler =
                new AuthenticationAuthCodeHandler(
                        dynamoAuthCodeService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        authenticationAttemptsService);
    }

    @Test
    void shouldReturn200AndSaveNewAuthCodeRequest() throws URISyntaxException {
        when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);

        var userProfile = new UserProfile();
        userProfile.setSubjectID(TEST_SUBJECT_ID);

        when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));

        var event = validAuthCodeRequest();

        var result = handler.handleRequest(event, context);

        verify(dynamoAuthCodeService, times(1))
                .saveAuthCode(
                        eq(userProfile.getSubjectID()),
                        anyString(),
                        anyList(),
                        eq(false),
                        anyString(),
                        eq(false),
                        eq(null));

        for (CountType countType : CountType.values()) {
            verify(authenticationAttemptsService)
                    .deleteCount(TEST_SUBJECT_ID, JourneyType.REAUTHENTICATION, countType);
        }

        assertThat(result, hasStatus(200));
        var jsonBody = new JSONObject(result.getBody());
        assertTrue(jsonBody.has(LOCATION));
        var location = jsonBody.get(LOCATION);
        var uri = new URI(location.toString());
        assertTrue(uri.getQuery().contains("code"));
        assertTrue(uri.getQuery().contains("state"));
        assertTrue(uri.getQuery().contains(TEST_STATE));
        assertFalse(uri.getQuery().contains("random_query_parameter"));
    }

    @Test
    void shouldReturn200AndSaveNewAuthCodeRequestWhenOptionalTimeStampPassedThrough()
            throws URISyntaxException {
        var body =
                format(
                        "{ \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\",  \"is-new-account\": \"%s\", \"password-reset-time\": \"%d\" }",
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email"),
                        TEST_SECTOR_IDENTIFIER,
                        false,
                        PASSWORD_RESET_TIME);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
        var userProfile = new UserProfile();
        userProfile.setSubjectID(TEST_SUBJECT_ID);
        when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(event, context);

        verify(dynamoAuthCodeService, times(1))
                .saveAuthCode(
                        eq(userProfile.getSubjectID()),
                        anyString(),
                        anyList(),
                        eq(false),
                        anyString(),
                        eq(false),
                        eq(PASSWORD_RESET_TIME));
        assertThat(result, hasStatus(200));
    }

    @Test
    void shouldReturn400ErrorWhenRedirectUriIsInvalid() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\" }",
                        CommonTestVariables.EMAIL, "");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenStateIsInvalid() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\" }",
                        CommonTestVariables.EMAIL, TEST_REDIRECT_URI, "");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorClaimsListIsEmpty() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"] }",
                        CommonTestVariables.EMAIL, TEST_REDIRECT_URI, TEST_STATE, Optional.empty());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenRPSectorUriIsInvalid() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\", }",
                        CommonTestVariables.EMAIL,
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email"),
                        "");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenUnableToFetchEmailFromUserProfile() throws Json.JsonException {
        when(authenticationService.getUserProfileByEmailMaybe(CommonTestVariables.EMAIL))
                .thenReturn(Optional.empty());
        var event = validAuthCodeRequest();

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1049)));
    }

    private APIGatewayProxyRequestEvent validAuthCodeRequest() {
        var body =
                format(
                        "{ \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\",  \"is-new-account\": \"%s\" }",
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email"),
                        TEST_SECTOR_IDENTIFIER,
                        false);
        return apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(CommonTestVariables.EMAIL)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }
}
