package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.AuthenticationAuthCodeHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthCodeExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.external.entity.AuthUserInfoClaims.EMAIL;
import static uk.gov.di.authentication.external.entity.AuthUserInfoClaims.EMAIL_VERIFIED;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationAuthCodeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_PASSWORD = "password-1";
    private static final String TEST_REDIRECT_URI = "https://redirect_uri.com";
    private static final String TEST_STATE = "xyz";
    private static final String TEST_AUTHORIZATION_CODE = "SplxlOBeZQQYbYS6WxSbIA";
    private static final String TEST_SECTOR_IDENTIFIER = "sectorIdentifier";
    private static final String TEST_JOURNEY_ID = "client-session-id";
    private static final String TEST_SUBJECT_ID = "subject-id";
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";

    @RegisterExtension
    protected static final AuthCodeExtension authCodeExtension = new AuthCodeExtension(180);

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new AuthenticationAuthCodeHandler(TEST_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    private void setUpDynamo() {
        authCodeExtension.saveAuthCode(
                TEST_SUBJECT_ID,
                TEST_AUTHORIZATION_CODE,
                List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                false,
                TEST_SECTOR_IDENTIFIER,
                false,
                TEST_JOURNEY_ID);
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
    }

    @Test
    void shouldReturn200StatusAndReturnMatchingAuthCodeForAuthCodeRequest()
            throws Json.JsonException {
        setUpDynamo();
        var sessionId = setupSession();
        var authRequest =
                new AuthCodeRequest(
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                        TEST_SECTOR_IDENTIFIER,
                        false,
                        null,
                        null);
        var response = makeRequest(Optional.of(authRequest), getHeaders(sessionId), Map.of());
        assertThat(response, hasStatus(200));
    }

    @Test
    void shouldReturn200StatusAndReturnMatchingAuthCodeForAuthCodeRequestWithNoClaims()
            throws Json.JsonException {
        setUpDynamo();
        var sessionId = setupSession();
        var authRequest =
                new AuthCodeRequest(
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        null,
                        TEST_SECTOR_IDENTIFIER,
                        false,
                        null,
                        null);
        var response = makeRequest(Optional.of(authRequest), getHeaders(sessionId), Map.of());
        assertThat(response, hasStatus(200));
    }

    @Test
    void shouldReturn400StatusForInvalidRedirectUri() throws Json.JsonException {
        setUpDynamo();
        var sessionId = setupSession();
        var authRequest =
                new AuthCodeRequest(
                        null,
                        TEST_STATE,
                        List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                        TEST_SECTOR_IDENTIFIER,
                        false,
                        null,
                        null);
        var response = makeRequest(Optional.of(authRequest), getHeaders(sessionId), Map.of());
        assertThat(response, hasStatus(400));
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsString(ErrorResponse.REQUEST_MISSING_PARAMS)));
    }

    @Test
    void shouldReturn400StatusForInvalidState() throws Json.JsonException {
        var sessionId = setupSession();
        setUpDynamo();
        var authRequest =
                new AuthCodeRequest(
                        TEST_REDIRECT_URI,
                        null,
                        List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                        TEST_SECTOR_IDENTIFIER,
                        false,
                        null,
                        null);
        var response = makeRequest(Optional.of(authRequest), getHeaders(sessionId), Map.of());
        assertThat(response, hasStatus(400));
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsString(ErrorResponse.REQUEST_MISSING_PARAMS)));
    }

    private Map<String, String> getHeaders(String sessionId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);
        return headers;
    }

    private String setupSession() {
        var sessionId = IdGenerator.generate();
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        return sessionId;
    }
}
