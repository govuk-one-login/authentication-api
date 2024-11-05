package uk.gov.di.authentication.external.services;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenServiceTest {
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService();
    }

    @Test
    void generateNewBearerTokenAndTokenResponseShouldGenerateBearerTokenButNoRefreshToken() {
        AccessTokenResponse response = tokenService.generateNewBearerTokenAndTokenResponse();

        assertNotNull(response);
        assertNotNull(response.getTokens());
        assertNotNull(response.getTokens().getBearerAccessToken());
        assertNull(response.getTokens().getRefreshToken());

        BearerAccessToken bearerAccessToken = response.getTokens().getBearerAccessToken();
        assertTrue(bearerAccessToken.getValue().length() > 0);
    }

    @Test
    void generateTokenErrorResponseShouldGenerateCorrectErrorResponse() {
        ErrorObject errorObject = new ErrorObject("invalid_request", "Invalid request parameters");

        HTTPResponse httpResponse = tokenService.generateTokenErrorResponse(errorObject);

        assertNotNull(httpResponse);
        assertEquals(400, httpResponse.getStatusCode());
        assertTrue(httpResponse.getBody().contains("invalid_request"));
        assertTrue(httpResponse.getBody().contains("Invalid request parameters"));
    }
}
