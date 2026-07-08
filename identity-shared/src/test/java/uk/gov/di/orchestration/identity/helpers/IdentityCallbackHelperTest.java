package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.IdentityAuditEventConfiguration;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.identity.services.IdentityProgressService;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.Metrics;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.identity.testsupport.TestAuditEvent.TEST_AUTH_CODE_ISSUED;
import static uk.gov.di.orchestration.identity.testsupport.TestAuditEvent.TEST_AUTH_REQUEST_RECEIVED;
import static uk.gov.di.orchestration.identity.testsupport.TestAuditEvent.TEST_SPOT_REQUESTED;
import static uk.gov.di.orchestration.identity.testsupport.TestAuditEvent.TEST_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.identity.testsupport.TestAuditEvent.TEST_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.identity.testsupport.TestAuditEvent.TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class IdentityCallbackHelperTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final AuthenticationUserInfoStorageService authUserInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private final LogoutService logoutService = mock(LogoutService.class);
    private final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CommonFrontend frontend = mock(CommonFrontend.class);
    private final IdentityProgressService identityProgressService =
            mock(IdentityProgressService.class);
    private final AuthCodeResponseGenerationService authCodeResponseService =
            mock(AuthCodeResponseGenerationService.class);
    private static final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private final Metrics metrics = mock(Metrics.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AwsSqsClient spotSqsClient = mock(AwsSqsClient.class);
    private final OidcAPI oidcAPI = mock(OidcAPI.class);
    private final IdentityCallbackHelper.TokenService tokenService =
            mock(IdentityCallbackHelper.TokenService.class);
    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final URI FRONT_END_IPV_CALLBACK_ERROR_URI =
            URI.create("https://example.com/ipv-callback-session-expiry-error");
    private static final URI FRONT_END_IPV_CALLBACK_URI =
            URI.create("https://example.com/ipv-callback");
    private static final URI FRONT_END_BASE_URI = URI.create("https://example.com");
    private static final String FRONT_END_AIS_LOGOUT_URL =
            FRONT_END_BASE_URI + "/unavailable-permanent";
    private static final String FRONT_END_SESSION_INVALID_LOGOUT_URL =
            FRONT_END_BASE_URI + "/signed-out";
    private static final URI OIDC_BASE_URL = URI.create("https://base-url.com");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final State RP_STATE = new State();
    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final State STATE = new State();
    private static final List<VectorOfTrust> VTR_LIST =
            List.of(
                    new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                    new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL));
    private static final ResponseMode RESPONSE_MODE = ResponseMode.QUERY;
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String AWS_REQUEST_ID = "test-request-id";
    private IdentityCallbackHelper helper;
    private static final ClientRegistry clientRegistry = generateClientRegistryNoClaims();
    private final UserInfo authUserInfo = generateAuthUserInfo();
    private final AuthenticationRequest authenticationRequest = generateAuthRequest(null);

    private static final Subject TEST_SUBJECT = new Subject();
    private static final String TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER =
            "urn:fdc:gov.uk:2022:0VzHWj9aaJpyHXJX8B5QJ-UOUibweHmkSg1GjF6w9yM";
    private static final String TEST_RP_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:_WJvfEzqmWo6vnDwSqgMPTC-aK8n_fkgZsNF-a4OxxU";
    private static final AccountIntervention NO_INTERVENTION =
            new AccountIntervention(new AccountInterventionState(false, false, false, false));
    private static final IdentityAuditEventConfiguration auditConfig =
            new IdentityAuditEventConfiguration(
                    TEST_AUTH_REQUEST_RECEIVED,
                    TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                    TEST_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                    TEST_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                    TEST_SPOT_REQUESTED,
                    TEST_AUTH_CODE_ISSUED);
    private static final TokenResponse SUCCESSFUL_TOKEN_RESPONSE =
            new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
    private static final TokenResponse UNSUCCESSFUL_TOKEN_RESPONSE = mock(TokenResponse.class);

    @RegisterExtension
    private final CaptureLoggingExtension redirectLogging =
            new CaptureLoggingExtension(RedirectService.class);

    private OrchSessionItem orchSession;
    private OrchClientSessionItem orchClientSession;

    @BeforeEach
    void setUp() throws Exception {
        usingValidAuthUserInfo();
        when(tokenService.getToken(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(UNSUCCESSFUL_TOKEN_RESPONSE.indicatesSuccess()).thenReturn(false);
        when(UNSUCCESSFUL_TOKEN_RESPONSE.toErrorResponse())
                .thenReturn(new TokenErrorResponse(new ErrorObject("1", "test-error-message")));
        when(frontend.errorURI()).thenReturn(FRONT_END_ERROR_URI);
        orchSession =
                new OrchSessionItem(SESSION_ID)
                        .withInternalCommonSubjectId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER);
        orchClientSession =
                new OrchClientSessionItem(
                                CLIENT_SESSION_ID,
                                authenticationRequest.toParameters(),
                                null,
                                List.of(
                                        new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                                        new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL)),
                                CLIENT_NAME)
                        .withRpPairwiseId(TEST_RP_PAIRWISE_ID);
        helper =
                new IdentityCallbackHelper(
                        configService,
                        authUserInfoStorageService,
                        auditService,
                        frontend,
                        identityProgressService,
                        tokenService,
                        oidcAPI,
                        authCodeResponseService,
                        orchAuthCodeService,
                        metrics,
                        dynamoIdentityService,
                        spotSqsClient,
                        orchSessionService,
                        logoutService,
                        accountInterventionService,
                        auditConfig);
    }

    @Test
    void shouldThrowExceptionWhenInternalCommonSubjectIdIsEmpty() {
        var orchSessionWithMissingIcsid = orchSession.withInternalCommonSubjectId(null);

        assertThrows(
                IdentityCallbackException.class,
                () -> {
                    helper.performIdentityJourney(
                            orchSessionWithMissingIcsid,
                            orchClientSession,
                            clientRegistry,
                            PERSISTENT_SESSION_ID,
                            IP_ADDRESS,
                            AUTH_CODE.getValue(),
                            authenticationRequest,
                            AWS_REQUEST_ID);
                });
    }

    @Test
    void shouldThrowExceptionWhenAuthUserInfoNotFound() throws Exception {
        when(authUserInfoStorageService.getAuthenticationUserInfo(any(), any()))
                .thenReturn(Optional.empty());

        assertThrows(
                IdentityCallbackException.class,
                () -> {
                    helper.performIdentityJourney(
                            orchSession,
                            orchClientSession,
                            clientRegistry,
                            PERSISTENT_SESSION_ID,
                            IP_ADDRESS,
                            AUTH_CODE.getValue(),
                            authenticationRequest,
                            AWS_REQUEST_ID);
                });
    }

    @Test
    void shouldThrowExceptionWhenTokenRequestIsNotSuccessful() throws Exception {
        when(tokenService.getToken(any())).thenReturn(UNSUCCESSFUL_TOKEN_RESPONSE);

        var response =
                helper.performIdentityJourney(
                        orchSession,
                        orchClientSession,
                        clientRegistry,
                        PERSISTENT_SESSION_ID,
                        IP_ADDRESS,
                        AUTH_CODE.getValue(),
                        authenticationRequest,
                        AWS_REQUEST_ID);

        assertAuditEventSent(TEST_AUTH_REQUEST_RECEIVED);
        assertAuditEventSent(TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);
    }

    private void assertAuditEventSent(AuditableEvent auditEvent) {
        verify(auditService).submitAuditEvent(eq(auditEvent), any(), any());
    }

    private void usingValidAuthUserInfo() throws ParseException {
        when(authUserInfoStorageService.getAuthenticationUserInfo(
                        TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER, CLIENT_SESSION_ID))
                .thenReturn(Optional.of(authUserInfo));
    }

    private UserInfo generateAuthUserInfo() {
        return new UserInfo(
                new JSONObject(
                        Map.of(
                                "sub",
                                TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER,
                                "client_session_id",
                                CLIENT_SESSION_ID,
                                "email",
                                TEST_EMAIL_ADDRESS,
                                "phone_number",
                                "012345678902",
                                "salt",
                                "TW1jNDhpbUV1TzVra1ZXN050WFZ0eDVoMG1iQ1RmWHNxWGRXdmJSTXpkdz0=",
                                "local_account_id",
                                TEST_SUBJECT.getValue())));
    }

    private static ClientRegistry generateClientRegistryNoClaims() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName("test-client")
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise");
    }

    private static ClientRegistry generateClientWithReturnCodes() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName("test-client")
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise")
                .withClaims(List.of("https://vocab.account.gov.uk/v1/returnCode"));
    }

    public static AuthenticationRequest generateAuthRequest(OIDCClaimsRequest oidcClaimsRequest) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(nonce)
                .claims(oidcClaimsRequest)
                .responseMode(RESPONSE_MODE)
                .build();
    }

    private void verifyAuditEvent(AuditableEvent auditableEvent) {
        verify(auditService)
                .submitAuditEvent(
                        auditableEvent,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withSessionId(SESSION_ID)
                                .withUserId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER)
                                .withEmail(TEST_EMAIL_ADDRESS)
                                .withPhone(authUserInfo.getPhoneNumber())
                                .withPersistentSessionId(PERSISTENT_SESSION_ID));
    }

    private void assertDoesRedirectToFrontendPage(
            APIGatewayProxyResponseEvent response, URI frontEndPage) {
        assertThat(response, hasStatus(302));
        assertEquals(frontEndPage.toString(), response.getHeaders().get("Location"));
    }
}
