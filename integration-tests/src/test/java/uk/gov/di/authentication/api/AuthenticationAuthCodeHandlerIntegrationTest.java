package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.AuthenticationAuthCodeHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthCodeExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.external.entity.AuthUserInfoClaims.EMAIL;
import static uk.gov.di.authentication.external.entity.AuthUserInfoClaims.EMAIL_VERIFIED;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationAuthCodeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_PASSWORD = "password-1";
    private static final String TEST_REDIRECT_URI = "https://redirect_uri.com";
    private static final String TEST_STATE = "xyz";
    private static final String TEST_AUTHORIZATION_CODE = "SplxlOBeZQQYbYS6WxSbIA";
    private static final String TEST_SECTOR_IDENTIFIER = "sectorIdentifier";
    private static final String TEST_SUBJECT_ID = "subject-id";

    @RegisterExtension
    protected static final AuthCodeExtension authCodeExtension = new AuthCodeExtension(180);

    @BeforeEach
    void setup() throws Json.JsonException {
        handler =
                new AuthenticationAuthCodeHandler(AUTH_CODE_HANDLER_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    private void setUpDynamo() {
        authCodeExtension.saveAuthCode(
                TEST_SUBJECT_ID,
                TEST_AUTHORIZATION_CODE,
                List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                false,
                TEST_SECTOR_IDENTIFIER,
                false);
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
    }

    @Test
    void shouldReturn200StatusAndReturnMatchingAuthCodeForAuthCodeRequest()
            throws Json.JsonException {
        setUpDynamo();
        var authRequest =
                new AuthCodeRequest(
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                        TEST_SECTOR_IDENTIFIER,
                        false);
        var response = makeRequest(Optional.of(authRequest), getHeaders(), Map.of());
        assertThat(response, hasStatus(200));
    }

    @Test
    void shouldReturn200StatusAndReturnMatchingAuthCodeForAuthCodeRequestWithNoClaims()
            throws Json.JsonException {
        setUpDynamo();
        var authRequest =
                new AuthCodeRequest(
                        TEST_REDIRECT_URI, TEST_STATE, null, TEST_SECTOR_IDENTIFIER, false);
        var response = makeRequest(Optional.of(authRequest), getHeaders(), Map.of());
        assertThat(response, hasStatus(200));
    }

    @Test
    void shouldReturn400StatusForInvalidRedirectUri() throws Json.JsonException {
        setUpDynamo();
        var authRequest =
                new AuthCodeRequest(
                        null,
                        TEST_STATE,
                        List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                        TEST_SECTOR_IDENTIFIER,
                        false);
        var response = makeRequest(Optional.of(authRequest), getHeaders(), Map.of());
        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400StatusForInvalidState() throws Json.JsonException {
        setUpDynamo();
        var authRequest =
                new AuthCodeRequest(
                        TEST_REDIRECT_URI,
                        null,
                        List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                        TEST_SECTOR_IDENTIFIER,
                        false);
        var response = makeRequest(Optional.of(authRequest), getHeaders(), Map.of());
        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    private Map<String, String> getHeaders() throws Json.JsonException {
        Map<String, String> headers = new HashMap<>();
        var sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        headers.put("Session-Id", sessionId);
        return headers;
    }
}
