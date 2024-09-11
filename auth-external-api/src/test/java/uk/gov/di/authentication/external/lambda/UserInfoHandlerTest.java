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
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent;
import uk.gov.di.authentication.external.services.UserInfoService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;

class UserInfoHandlerTest {
    private ConfigurationService configurationService;
    private UserInfoService userInfoService;
    private AccessTokenService accessTokenService;
    private UserInfoHandler userInfoHandler;
    private SessionService sessionService;
    private static final AccessTokenStore accessTokenStore = mock(AccessTokenStore.class);
    private static final Subject TEST_SUBJECT = new Subject();
    private static final UserInfo TEST_SUBJECT_USER_INFO = new UserInfo(TEST_SUBJECT);
    private final AuditService auditService = mock(AuditService.class);
    private final String sessionId = "a-session-id";
    private final Session testSession = new Session(sessionId);
    private final SerializationService objectMapper = SerializationService.getInstance();

    @BeforeEach
    public void setUp() {
        when(accessTokenStore.isUsed()).thenReturn(false);
        long sixteenthAugust2099UnixTime = 4090554490L;
        when(accessTokenStore.getTimeToExist()).thenReturn(sixteenthAugust2099UnixTime);

        configurationService = mock(ConfigurationService.class);
        userInfoService = mock(UserInfoService.class);
        accessTokenService = mock(AccessTokenService.class);
        sessionService = mock(SessionService.class);
        when(accessTokenService.getAccessTokenStore(any()))
                .thenReturn(Optional.of(accessTokenStore));
        userInfoHandler =
                new UserInfoHandler(
                        configurationService,
                        userInfoService,
                        accessTokenService,
                        auditService,
                        sessionService);

        TEST_SUBJECT_USER_INFO.setEmailAddress("test@test.com");
        TEST_SUBJECT_USER_INFO.setPhoneNumber("0123456789");
        when(accessTokenStore.getSubjectID()).thenReturn("testSubjectId");
    }

    @Test
    void shouldReturn200WithUserInfoForValidRequestAndSetTokenStoreUsed()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validTokenHeader = "Bearer valid-token";
        AccessToken validToken = AccessToken.parse(validTokenHeader, AccessTokenType.BEARER);
        request.setHeaders(Map.of("Authorization", validTokenHeader, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(validToken);
        when(userInfoService.populateUserInfo(accessTokenStore)).thenReturn(TEST_SUBJECT_USER_INFO);
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);
        Session updatedSession = testSession.setNewAccount(Session.AccountState.EXISTING);

        assertEquals(200, response.getStatusCode());
        assertTrue(
                response.getBody()
                        .contains(String.format("\"sub\":\"%s\"", TEST_SUBJECT.getValue())));

        verify(sessionService).getSessionFromRequestHeaders(request.getHeaders());
        verify(accessTokenService, times(1)).setAccessTokenStoreUsed(validToken.getValue(), true);
        verify(auditService)
                .submitAuditEvent(
                        AuthExternalApiAuditableEvent.AUTH_USERINFO_SENT_TO_ORCHESTRATION,
                        new AuditContext(
                                "",
                                "",
                                "",
                                TEST_SUBJECT.getValue(),
                                "test@test.com",
                                "",
                                "0123456789",
                                "",
                                Optional.empty()));
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

        verify(accessTokenService, never()).setAccessTokenStoreUsed(any(), anyBoolean());
    }

    @Test
    void shouldReturnNoSessionWhenNoSessionIdHeaderAttached()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validTokenHeader = "Bearer valid-token";
        AccessToken validToken = AccessToken.parse(validTokenHeader, AccessTokenType.BEARER);
        request.setHeaders(Map.of("Authorization", validTokenHeader));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(validToken);
        when(userInfoService.populateUserInfo(accessTokenStore)).thenReturn(TEST_SUBJECT_USER_INFO);

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertEquals(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000), response.getBody());
        verify(sessionService).getSessionFromRequestHeaders(request.getHeaders());
        verifyNoInteractions(accessTokenService, userInfoService, auditService);
    }

    @Test
    void shouldReturnNoSessionWhenSessionNotFound() throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validTokenHeader = "Bearer valid-token";
        AccessToken validToken = AccessToken.parse(validTokenHeader, AccessTokenType.BEARER);
        request.setHeaders(Map.of("Authorization", validTokenHeader, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(validToken);
        when(userInfoService.populateUserInfo(accessTokenStore)).thenReturn(TEST_SUBJECT_USER_INFO);
        when(sessionService.getSessionFromRequestHeaders(any())).thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertEquals(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000), response.getBody());
        verify(sessionService).getSessionFromRequestHeaders(request.getHeaders());
        verifyNoInteractions(accessTokenService, userInfoService, auditService);
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenBearerTokenCannotBeParsed()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String invalidToken = "Bearer this-is-not-a-valid-token";
        request.setHeaders(Map.of("Authorization", invalidToken, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenThrow(new AccessTokenException("test", BearerTokenError.INVALID_TOKEN));
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));

        verify(accessTokenService, never()).setAccessTokenStoreUsed(any(), anyBoolean());
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenTokenNotFoundInDatabase()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String invalidToken = "Bearer this-is-not-a-valid-token";
        request.setHeaders(Map.of("Authorization", invalidToken, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(invalidToken, AccessTokenType.BEARER));
        when(accessTokenService.getAccessTokenStore(any())).thenReturn(Optional.empty());
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));

        verify(accessTokenService, never()).setAccessTokenStoreUsed(any(), anyBoolean());
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenAccessTokenHasAlreadyBeenUsed()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validToken = "Bearer valid-token";
        request.setHeaders(Map.of("Authorization", validToken, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(validToken, AccessTokenType.BEARER));
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

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

        verify(accessTokenService, never()).setAccessTokenStoreUsed(any(), anyBoolean());
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenAccessTokenIsTooOld()
            throws ParseException, AccessTokenException {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validToken = "Bearer valid-token";
        request.setHeaders(Map.of("Authorization", validToken, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(AccessToken.parse(validToken, AccessTokenType.BEARER));
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

        when(accessTokenStore.getTimeToExist()).thenReturn(0L);

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(401, response.getStatusCode());
        Map<String, List<String>> multiValueHeaders = response.getMultiValueHeaders();
        assertNotNull(multiValueHeaders);
        var authChallengeHeader = multiValueHeaders.get("WWW-Authenticate");
        assertTrue(authChallengeHeader.get(0).contains("invalid_token"));
        assertTrue(authChallengeHeader.get(0).contains("\"Invalid access token\""));

        verify(accessTokenService, never()).setAccessTokenStoreUsed(any(), anyBoolean());
    }
}
