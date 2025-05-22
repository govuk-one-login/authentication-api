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
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
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
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
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
    private AuthSessionService authSessionService;
    private static final AccessTokenStore accessTokenStore = mock(AccessTokenStore.class);
    private static final Subject TEST_SUBJECT = new Subject();
    private static final UserInfo TEST_SUBJECT_USER_INFO = new UserInfo(TEST_SUBJECT);
    private final AuditService auditService = mock(AuditService.class);
    private final String sessionId = "a-session-id";
    private final Session testSession = new Session();
    private final AuthSessionItem authSession = new AuthSessionItem().withSessionId(sessionId);
    private final SerializationService objectMapper = SerializationService.getInstance();
    private final String testVerifiedMfaMethodType = MFAMethodType.AUTH_APP.getValue();
    private final CredentialTrustLevel testCurrentCredentialStrength =
            CredentialTrustLevel.MEDIUM_LEVEL;

    @BeforeEach
    public void setUp() {
        when(accessTokenStore.isUsed()).thenReturn(false);
        long sixteenthAugust2099UnixTime = 4090554490L;
        when(accessTokenStore.getTimeToExist()).thenReturn(sixteenthAugust2099UnixTime);

        configurationService = mock(ConfigurationService.class);
        userInfoService = mock(UserInfoService.class);
        accessTokenService = mock(AccessTokenService.class);
        sessionService = mock(SessionService.class);
        authSessionService = mock(AuthSessionService.class);
        when(accessTokenService.getAccessTokenStore(any()))
                .thenReturn(Optional.of(accessTokenStore));
        userInfoHandler =
                new UserInfoHandler(
                        configurationService,
                        userInfoService,
                        accessTokenService,
                        auditService,
                        sessionService,
                        authSessionService);

        TEST_SUBJECT_USER_INFO.setEmailAddress("test@test.com");
        TEST_SUBJECT_USER_INFO.setPhoneNumber("0123456789");
        TEST_SUBJECT_USER_INFO.setClaim("verified_mfa_method_type", testVerifiedMfaMethodType);
        TEST_SUBJECT_USER_INFO.setClaim(
                "current_credential_strength", testCurrentCredentialStrength);
        when(accessTokenStore.getSubjectID()).thenReturn("testSubjectId");
    }

    @Test
    void shouldReturn200WithUserInfoForValidRequestAndSetTokenStoreUsed()
            throws ParseException, AccessTokenException {
        withAuthSession();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validTokenHeader = "Bearer valid-token";
        AccessToken validToken = AccessToken.parse(validTokenHeader, AccessTokenType.BEARER);
        request.setHeaders(Map.of("Authorization", validTokenHeader, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(validToken);
        when(userInfoService.populateUserInfo(eq(accessTokenStore), any()))
                .thenReturn(TEST_SUBJECT_USER_INFO);
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(200, response.getStatusCode());
        assertTrue(
                response.getBody()
                        .contains(String.format("\"sub\":\"%s\"", TEST_SUBJECT.getValue())));
        assertClaimsInResponse(response.getBody());

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
    void shouldUpdateAuthSessionWithAccountStateExisting()
            throws ParseException, AccessTokenException {
        withAuthSession();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String validTokenHeader = "Bearer valid-token";
        AccessToken validToken = AccessToken.parse(validTokenHeader, AccessTokenType.BEARER);
        request.setHeaders(Map.of("Authorization", validTokenHeader, SESSION_ID_HEADER, sessionId));
        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(validToken);
        when(userInfoService.populateUserInfo(any(), any())).thenReturn(TEST_SUBJECT_USER_INFO);
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(200, response.getStatusCode());
        assertTrue(
                response.getBody()
                        .contains(String.format("\"sub\":\"%s\"", TEST_SUBJECT.getValue())));
        assertClaimsInResponse(response.getBody());

        verify(accessTokenService, times(1)).setAccessTokenStoreUsed(validToken.getValue(), true);
        verify(authSessionService)
                .updateSession(
                        argThat(t -> t.getIsNewAccount() == AuthSessionItem.AccountState.EXISTING));

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
        withAuthSession();
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
        when(userInfoService.populateUserInfo(accessTokenStore, authSession))
                .thenReturn(TEST_SUBJECT_USER_INFO);

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
        when(userInfoService.populateUserInfo(accessTokenStore, authSession))
                .thenReturn(TEST_SUBJECT_USER_INFO);
        when(sessionService.getSessionFromRequestHeaders(any())).thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertEquals(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000), response.getBody());
        verify(sessionService).getSessionFromRequestHeaders(request.getHeaders());
        verifyNoInteractions(accessTokenService, userInfoService, auditService);
    }

    @Test
    void shouldReturn400WhenNoAuthSessionPresent() throws ParseException, AccessTokenException {
        withNoAuthSession();
        String validTokenHeader = "Bearer valid-token";
        AccessToken validToken = AccessToken.parse(validTokenHeader, AccessTokenType.BEARER);

        when(accessTokenService.getAccessTokenFromAuthorizationHeader(any()))
                .thenReturn(validToken);
        when(userInfoService.populateUserInfo(accessTokenStore, authSession))
                .thenReturn(TEST_SUBJECT_USER_INFO);
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(testSession));
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("Authorization", validTokenHeader, SESSION_ID_HEADER, sessionId));

        APIGatewayProxyResponseEvent response = userInfoHandler.userInfoRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertEquals(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000), response.getBody());
        verify(sessionService).getSessionFromRequestHeaders(request.getHeaders());
        verifyNoInteractions(accessTokenService, userInfoService, auditService);
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenBearerTokenCannotBeParsed()
            throws ParseException, AccessTokenException {
        withAuthSession();
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
        withAuthSession();
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
        withAuthSession();
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
        withAuthSession();
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

    private void withAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(
                        Optional.of(
                                new AuthSessionItem()
                                        .withSessionId(sessionId)
                                        .withAccountState(AuthSessionItem.AccountState.NEW)));
    }

    private void withNoAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.empty());
    }

    private void assertClaimsInResponse(String responseBody) {
        assertTrue(
                responseBody.contains(
                        String.format(
                                "\"verified_mfa_method_type\":\"%s\"", testVerifiedMfaMethodType)));
        assertTrue(
                responseBody.contains(
                        String.format(
                                "\"current_credential_strength\":\"%s\"",
                                testCurrentCredentialStrength)));
    }
}
