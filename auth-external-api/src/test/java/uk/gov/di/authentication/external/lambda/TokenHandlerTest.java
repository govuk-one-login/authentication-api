package uk.gov.di.authentication.external.lambda;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent;
import uk.gov.di.authentication.external.services.TokenService;
import uk.gov.di.authentication.external.validators.TokenRequestValidator;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.*;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenHandlerTest {
    private TokenHandler tokenHandler;
    private static ConfigurationService configurationService;
    private AccessTokenService accessTokenService;
    private TokenRequestValidator tokenRequestValidator;
    private static final ClientSubjectHelper clientSubjectHelper = mock(ClientSubjectHelper.class);
    private static final TokenService tokenUtilityService = mock(TokenService.class);
    private static final AuditService auditService = mock(AuditService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final BearerAccessToken SUCCESS_TOKEN_RESPONSE_ACCESS_TOKEN =
            new BearerAccessToken();
    private static final AccessTokenResponse SUCCESS_TOKEN_RESPONSE =
            new AccessTokenResponse(new Tokens(SUCCESS_TOKEN_RESPONSE_ACCESS_TOKEN, null));
    private static final DynamoAuthCodeService authCodeService = mock(DynamoAuthCodeService.class);
    private static final long UNIX_TIME_16_08_2099 = 4090554490L;
    private static final String VALID_AUTH_CODE = "valid-auth-code";
    private static final String SUBJECT_ID = "any";
    private static final String CLIENT_ID = "test-client-id";
    private static final Long PASSWORD_RESET_TIME = 1710255274L;
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final UserProfile USER_PROFILE =
            new UserProfile().withSubjectID("any").withSalt(ByteBuffer.allocateDirect(12345));
    private static final AuthCodeStore VALID_AUTH_CODE_STORE =
            new AuthCodeStore()
                    .withAuthCode(VALID_AUTH_CODE)
                    .withIsNewAccount(true)
                    .withSectorIdentifier("any")
                    .withClaims(List.of("any"))
                    .withSubjectID("any")
                    .withHasBeenUsed(false)
                    .withTimeToExist(UNIX_TIME_16_08_2099)
                    .withPasswordResetTime(PASSWORD_RESET_TIME)
                    .withJourneyID(CLIENT_SESSION_ID);
    private static final String USED_AUTH_CODE = "used-auth-code";
    private static final AuthCodeStore USED_AUTH_CODE_STORE =
            new AuthCodeStore()
                    .withAuthCode(USED_AUTH_CODE)
                    .withIsNewAccount(true)
                    .withSectorIdentifier("any")
                    .withClaims(List.of("any"))
                    .withSubjectID("any")
                    .withHasBeenUsed(true)
                    .withTimeToExist(UNIX_TIME_16_08_2099);
    private static final String EXPIRED_AUTH_CODE = "expired-auth-code";
    private static final AuthCodeStore EXPIRED_AUTH_CODE_STORE =
            new AuthCodeStore()
                    .withAuthCode(EXPIRED_AUTH_CODE)
                    .withIsNewAccount(true)
                    .withSectorIdentifier("any")
                    .withClaims(List.of("any"))
                    .withSubjectID("any")
                    .withHasBeenUsed(false)
                    .withTimeToExist(0L);

    @BeforeAll
    public static void init() {
        when(authCodeService.getAuthCodeStore(VALID_AUTH_CODE))
                .thenReturn(Optional.of(VALID_AUTH_CODE_STORE));
        when(authCodeService.getAuthCodeStore(EXPIRED_AUTH_CODE))
                .thenReturn(Optional.of(EXPIRED_AUTH_CODE_STORE));
        when(authCodeService.getAuthCodeStore(USED_AUTH_CODE))
                .thenReturn(Optional.of(USED_AUTH_CODE_STORE));

        when(tokenUtilityService.generateNewBearerTokenAndTokenResponse())
                .thenReturn(SUCCESS_TOKEN_RESPONSE);
        when(tokenUtilityService.generateTokenErrorResponse(any())).thenCallRealMethod();

        when(dynamoService.getUserProfileFromSubject(any())).thenReturn(USER_PROFILE);
    }

    @BeforeEach
    public void setUp() {
        configurationService = mock(ConfigurationService.class);
        when(configurationService.getAuthenticationAuthCallbackURI())
                .thenReturn(URI.create("https://test-callback.com"));
        when(configurationService.getAuthenticationBackendURI())
                .thenReturn(URI.create("https://test-backend.com"));
        when(configurationService.getOrchestrationBackendURI())
                .thenReturn(URI.create("https://orch-test-backend.com"));
        when(configurationService.getInternalSectorUri()).thenReturn("https://test-backend.com");

        accessTokenService = mock(AccessTokenService.class);
        tokenRequestValidator = mock(TokenRequestValidator.class);

        tokenHandler =
                new TokenHandler(
                        configurationService,
                        authCodeService,
                        accessTokenService,
                        tokenUtilityService,
                        tokenRequestValidator,
                        auditService,
                        dynamoService);
    }

    @Test
    void shouldReturn400WithErrorMessageWhenQueryParamIsMissingOrInvalid() {
        String testErrorDescription = "test-error-description";
        when(tokenRequestValidator.validatePlaintextParams(any()))
                .thenReturn(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE, testErrorDescription)));
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = tokenHandler.tokenRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST_CODE));
        assertTrue(response.getBody().contains(testErrorDescription));
    }

    @Test
    void shouldReturn400WithErrorMessageWhenClientAssertionJwtCannotBeValidated()
            throws TokenAuthInvalidException {
        String testErrorDescription = "test-error-description";

        doThrow(
                        new TokenAuthInvalidException(
                                new ErrorObject(
                                        OAuth2Error.INVALID_CLIENT_CODE, testErrorDescription),
                                ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                "tbc"))
                .when(tokenRequestValidator)
                .validatePrivateKeyJwtClientAuth(any(), any(), any());
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = tokenHandler.tokenRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_CLIENT_CODE));
        assertTrue(response.getBody().contains(testErrorDescription));
    }

    @Test
    void shouldReturn400WithErrorMessageWhenAuthCodeNotFoundInDataStore() {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String formData = "code=" + "auth-code-not-registered-for-mock-auth-code-store-service";
        request.setBody(formData);

        APIGatewayProxyResponseEvent response = tokenHandler.tokenRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST.getCode()));
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST.getDescription()));
    }

    @Test
    void shouldReturn400WithErrorMessageWhenAuthCodeHasAlreadyBeenUsed() {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String formData = "code=" + USED_AUTH_CODE;
        request.setBody(formData);

        APIGatewayProxyResponseEvent response = tokenHandler.tokenRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST.getCode()));
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST.getDescription()));
    }

    @Test
    void shouldReturn400WithErrorMessageWhenAuthCodeHasExpired() {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String formData = "code=" + EXPIRED_AUTH_CODE;
        request.setBody(formData);

        APIGatewayProxyResponseEvent response = tokenHandler.tokenRequestHandler(request);

        assertEquals(400, response.getStatusCode());
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST.getCode()));
        assertTrue(response.getBody().contains(OAuth2Error.INVALID_REQUEST.getDescription()));
    }

    @Test
    void shouldReturn200WithAccessTokenWhenAuthCodeStoreIsValidAndMarkAuthCodeStoreAsUsed() {
        String internalPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT_ID,
                        "test-backend.com",
                        SdkBytes.fromByteBuffer(ByteBuffer.allocateDirect(12345)).asByteArray());
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        String formData = "code=" + VALID_AUTH_CODE + "&client_id=" + CLIENT_ID;
        request.setBody(formData);

        APIGatewayProxyResponseEvent response = tokenHandler.tokenRequestHandler(request);

        assertEquals(200, response.getStatusCode());
        assertTrue(response.getBody().contains(SUCCESS_TOKEN_RESPONSE_ACCESS_TOKEN.getValue()));
        assertTrue(response.getBody().contains("\"token_type\":\"Bearer\""));
        verify(accessTokenService)
                .addAccessTokenStore(
                        SUCCESS_TOKEN_RESPONSE_ACCESS_TOKEN.getValue(),
                        VALID_AUTH_CODE_STORE.getSubjectID(),
                        VALID_AUTH_CODE_STORE.getClaims(),
                        VALID_AUTH_CODE_STORE.getIsNewAccount(),
                        VALID_AUTH_CODE_STORE.getSectorIdentifier(),
                        VALID_AUTH_CODE_STORE.getPasswordResetTime());
        verify(authCodeService).updateHasBeenUsed(VALID_AUTH_CODE, true);

        verify(auditService)
                .submitAuditEvent(
                        AuthExternalApiAuditableEvent.AUTH_TOKEN_SENT_TO_ORCHESTRATION,
                        new AuditContext(
                                CLIENT_ID,
                                CLIENT_SESSION_ID,
                                AuditService.UNKNOWN,
                                internalPairwiseId,
                                AuditService.UNKNOWN,
                                AuditService.UNKNOWN,
                                AuditService.UNKNOWN,
                                AuditService.UNKNOWN,
                                Optional.empty()));
    }
}
