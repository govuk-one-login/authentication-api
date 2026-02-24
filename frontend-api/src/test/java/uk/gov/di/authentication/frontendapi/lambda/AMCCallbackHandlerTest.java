package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCCallbackRequest;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.frontendapi.entity.amc.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.services.AMCService;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.AMC_TOKEN_RESPONSE_ERROR;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.AMC_TOKEN_UNEXPECTED_ERROR;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class AMCCallbackHandlerTest {
    private static final Context CONTEXT = mock(Context.class);
    private static final UserContext USER_CONTEXT = mock(UserContext.class);

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private static final AMCService AMC_SERVICE = mock(AMCService.class);
    private static TokenRequest tokenRequest;
    private static AMCCallbackHandler handler;

    private static final String STATE = "state";
    private static final String AUTH_CODE = "1234";
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String SUCCESSFUL_TOKEN_RESPONSE =
            """
                    {
                        "access_token": "%s",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }
                    """
                    .formatted(ACCESS_TOKEN);
    public static final String JOURNEY_OUTCOME_RESULT =
            """
                            {
                              "outcome_id": "9cd4c45f8f33cced99cfaa48394e1acf5e90f6e2616bba40",
                              "sub": "urn:fdc:gov.uk:2022:JG0RJI1pYbnanbvPs-j4j5-a-PFcmhry9Qu9NCEp5d4",
                              "email": "user@example.com",
                              "scope": "account-delete",
                              "success": true,
                              "journeys": [
                                {
                                  "journey": "account-delete",
                                  "timestamp": 1760718467000,
                                  "success": true,
                                  "details": {}
                                }
                              ]
                            }
                    """;

    @BeforeAll
    static void setUp() {
        tokenRequest = mock(TokenRequest.class);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        handler =
                new AMCCallbackHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        AMC_SERVICE);
    }

    @BeforeEach
    void resetMocks() {
        reset(AMC_SERVICE);
    }

    @Test
    void shouldReturn200WhenTokenResponseSuccessful() throws IOException, ParseException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE)).thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, SUCCESSFUL_TOKEN_RESPONSE);

        var successfulJourneyOutcomeHttpResponse = new HTTPResponse(200);
        successfulJourneyOutcomeHttpResponse.setContent(JOURNEY_OUTCOME_RESULT);

        when(AMC_SERVICE.requestJourneyOutcome(
                        argThat(
                                userInfoRequest ->
                                        userInfoRequest
                                                .getAccessToken()
                                                .toString()
                                                .equals(ACCESS_TOKEN))))
                .thenReturn(Result.success(successfulJourneyOutcomeHttpResponse));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertEquals(JOURNEY_OUTCOME_RESULT, result.getBody());
    }

    @Test
    void shouldReturn400WhenTokenResponseUnsuccessful() {
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE))
                .thenReturn(Result.failure(JwtFailureReason.JWT_ENCODING_ERROR));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(400, result.getStatusCode());
    }

    @Test
    void shouldReturn500WhenErrorRetrievingToken() throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE)).thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 500, "error from token response");

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(AMC_TOKEN_RESPONSE_ERROR));
    }

    @Test
    void shouldReturn500WhenErrorResponseCannotBeParsedAsTokenResponse()
            throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE)).thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, "{\"foo\": \"not a token response\"}");

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(AMC_TOKEN_UNEXPECTED_ERROR));
    }

    @Test
    void shouldReturn500WhenIOExceptionCallingTokenEndpoint() throws IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE)).thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(httpRequest.send()).thenThrow(new IOException("Uh oh"));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(AMC_TOKEN_UNEXPECTED_ERROR));
    }

    @Test
    void shouldReturn400WhenJourneyOutcomeResponseUnsuccessful()
            throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE)).thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, SUCCESSFUL_TOKEN_RESPONSE);

        when(AMC_SERVICE.requestJourneyOutcome(
                        argThat(
                                userInfoRequest ->
                                        userInfoRequest
                                                .getAccessToken()
                                                .toString()
                                                .equals(ACCESS_TOKEN))))
                .thenReturn(
                        Result.failure(JourneyOutcomeError.ERROR_RESPONSE_FROM_JOURNEY_OUTCOME));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(400, result.getStatusCode());
    }

    @Test
    void shouldReturn500WhenJourneyOutcomeResponseGetsIOException()
            throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE)).thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, SUCCESSFUL_TOKEN_RESPONSE);

        when(AMC_SERVICE.requestJourneyOutcome(
                        argThat(
                                userInfoRequest ->
                                        userInfoRequest
                                                .getAccessToken()
                                                .toString()
                                                .equals(ACCESS_TOKEN))))
                .thenReturn(Result.failure(JourneyOutcomeError.IO_EXCEPTION));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
    }

    private void setupTokenHttpResponse(
            HTTPRequest httpRequest, int tokenResponseCode, String tokenResponseBody)
            throws ParseException, IOException {
        var httpResponse = new HTTPResponse(tokenResponseCode);
        httpResponse.setContentType("application/json");
        httpResponse.setContent(tokenResponseBody);
        when(httpRequest.send()).thenReturn(httpResponse);
    }
}
