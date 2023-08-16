package uk.gov.di.authentication.external.lambda;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.external.services.UserInfoService;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserInfoHandlerTest {
    private ConfigurationService configurationService;
    private UserInfoService userInfoService;
    private AccessTokenService accessTokenService;
    private UserInfoHandler userInfoHandler;
    private static final AccessTokenStore accessTokenStore = mock(AccessTokenStore.class);
    private static final Subject TEST_SUBJECT = new Subject();
    private static final UserInfo TEST_SUBJECT_USER_INFO = new UserInfo(TEST_SUBJECT);

    @BeforeEach
    public void setUp() {
        when(accessTokenStore.isUsed()).thenReturn(false);
        long sixteenthAugust2099UnixTime = 4090554490L;
        when(accessTokenStore.getTimeToExist()).thenReturn(sixteenthAugust2099UnixTime);

        configurationService = mock(ConfigurationService.class);
        userInfoService = mock(UserInfoService.class);
        accessTokenService = mock(AccessTokenService.class);
        when(accessTokenService.getAccessTokenStore(any()))
                .thenReturn(Optional.of(accessTokenStore));

        userInfoHandler =
                new UserInfoHandler(configurationService, userInfoService, accessTokenService);
    }

    @Test
    void shouldReturn200WithUserInfoForValidRequest() throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validToken = "Bearer valid-token";
        request.setHeaders(Map.of("Authorization", validToken));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(validToken, AccessTokenType.BEARER));
        when(userInfoService.populateUserInfo(accessTokenStore)).thenReturn(TEST_SUBJECT_USER_INFO);

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(200, response.getStatusCode());
        assertEquals(
                String.format("{\"sub\":\"%s\"}", TEST_SUBJECT.getValue()), response.getBody());
    }

    @Test
    void shouldReturnMissingTokenErrorWhenAuthHeaderNotFound() {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertEquals("Bearer", authChallengeHeader.get(0));
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenBearerTokenCannotBeParsed()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String invalidToken = "Bearer this-is-not-a-valid-token";
        request.setHeaders(Map.of("Authorization", invalidToken));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenThrow(new AccessTokenException("test", BearerTokenError.INVALID_TOKEN));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenTokenNotFoundInDatabase()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String invalidToken = "Bearer this-is-not-a-valid-token";
        request.setHeaders(Map.of("Authorization", invalidToken));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(invalidToken, AccessTokenType.BEARER));
        when(accessTokenService.getAccessTokenStore(any())).thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenAccessTokenHasAlreadyBeenUsed()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validToken = "Bearer valid-token";
        request.setHeaders(Map.of("Authorization", validToken));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(validToken, AccessTokenType.BEARER));

        AccessTokenStore mockAccessTokenStore = mock(AccessTokenStore.class);
        when(mockAccessTokenStore.isUsed()).thenReturn(true);
        when(accessTokenService.getAccessTokenStore(any()))
                .thenReturn(Optional.of(mockAccessTokenStore));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenAccessTokenIsTooOld()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validToken = "Bearer valid-token";
        request.setHeaders(Map.of("Authorization", validToken));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(validToken, AccessTokenType.BEARER));

        when(accessTokenStore.getTimeToExist()).thenReturn(0L);

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));
    }
}
