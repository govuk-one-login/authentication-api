package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IpvCallbackException;
import uk.gov.di.authentication.ipv.helpers.IPVCallbackHelper;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OrchFrontend;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.NoSessionEntity;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.CORE_IDENTITY_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.CREDENTIAL_JWT_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final IPVAuthorisationService responseService = mock(IPVAuthorisationService.class);
    private final IPVTokenService ipvTokenService = mock(IPVTokenService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final AuthenticationUserInfoStorageService authUserInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private final LogoutService logoutService = mock(LogoutService.class);
    private final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private final IPVCallbackHelper ipvCallbackHelper = mock(IPVCallbackHelper.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final CommonFrontend frontend = mock(CommonFrontend.class);
    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final URI FRONT_END_IPV_CALLBACK_ERROR_URI =
            URI.create("https://example.com/ipv-callback-session-expiry-error");
    private static final URI FRONT_END_IPV_CALLBACK_URI =
            URI.create("https://example.com/ipv-callback");
    private static final URI OIDC_BASE_URL = URI.create("https://base-url.com");
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String REQUEST_ID = "a-request-id";
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final State RP_STATE = new State();
    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final Subject PUBLIC_SUBJECT =
            new Subject("TsEVC7vg0NPAmzB33vRUFztL2c0-fecKWKcc73fuDhc");
    private static final State STATE = new State();
    private static final List<VectorOfTrust> VTR_LIST =
            List.of(
                    new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                    new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL));
    private IPVCallbackHandler handler;
    private static final byte[] salt =
            "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes(StandardCharsets.UTF_8);
    private final String redirectUriErrorMessage = "redirect_uri param must be provided";
    private final URI accessDeniedURI =
            new AuthenticationErrorResponse(
                            URI.create(REDIRECT_URI.toString()),
                            OAuth2Error.ACCESS_DENIED,
                            RP_STATE,
                            null)
                    .toURI();
    private final ClientRegistry clientRegistry = generateClientRegistryNoClaims();
    private final UserProfile userProfile = generateUserProfile();

    private static final Subject TEST_SUBJECT = new Subject();
    private static final String TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_SUBJECT.getValue(), "test.account.gov.uk", salt);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(IPVCallbackHandler.class);

    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setInternalCommonSubjectIdentifier(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER);

    private final OrchSessionItem orchSession = new OrchSessionItem(SESSION_ID);

    private final ClientSession clientSession =
            new ClientSession(
                    generateAuthRequest(new OIDCClaimsRequest()).toParameters(),
                    null,
                    List.of(
                            new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL)),
                    CLIENT_NAME);

    private final Json objectMapper = SerializationService.getInstance();

    private static Stream<Arguments> additionalClaims() {
        return Stream.of(
                Arguments.of(Map.of(ValidClaims.ADDRESS.getValue(), ADDRESS_CLAIM)),
                Arguments.of(Map.of(ValidClaims.PASSPORT.getValue(), PASSPORT_CLAIM)),
                Arguments.of(emptyMap()),
                Arguments.of(
                        Map.of(
                                ValidClaims.ADDRESS.getValue(),
                                ADDRESS_CLAIM,
                                ValidClaims.PASSPORT.getValue(),
                                PASSPORT_CLAIM)));
    }

    private static Stream<Arguments> returnCodeClaims() {
        var claimsSetRequest =
                new ClaimsSetRequest()
                        .add(ValidClaims.ADDRESS.getValue())
                        .add(ValidClaims.PASSPORT.getValue())
                        .add(ValidClaims.CORE_IDENTITY_JWT.getValue());
        var oidcValidClaimsRequestWithoutReturnCode =
                new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);

        var oidcValidClaimsRequestWithReturnCode =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                claimsSetRequest.add(ValidClaims.RETURN_CODE.getValue()));

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI();

        return Stream.of(
                Arguments.of(
                        generateClientRegistryNoClaims(),
                        oidcValidClaimsRequestWithoutReturnCode,
                        expectedURI),
                Arguments.of(
                        generateClientRegistryNoClaims(),
                        oidcValidClaimsRequestWithReturnCode,
                        expectedURI),
                Arguments.of(
                        generateClientWithReturnCodes(),
                        oidcValidClaimsRequestWithoutReturnCode,
                        expectedURI),
                Arguments.of(
                        generateClientWithReturnCodes(),
                        oidcValidClaimsRequestWithReturnCode,
                        REDIRECT_URI));
    }

    @BeforeEach
    void setUp() {
        handler =
                new IPVCallbackHandler(
                        configService,
                        responseService,
                        ipvTokenService,
                        sessionService,
                        orchSessionService,
                        authUserInfoStorageService,
                        dynamoService,
                        clientSessionService,
                        dynamoClientService,
                        auditService,
                        logoutService,
                        accountInterventionService,
                        noSessionOrchestrationService,
                        ipvCallbackHelper,
                        frontend);
        when(frontend.ipvCallbackURI()).thenReturn(FRONT_END_IPV_CALLBACK_URI);
        when(frontend.errorIpvCallbackURI()).thenReturn(FRONT_END_IPV_CALLBACK_ERROR_URI);
        when(frontend.errorURI()).thenReturn(FRONT_END_ERROR_URI);
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(configService.isIdentityEnabled()).thenReturn(true);
        when(configService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(accountInterventionService.getAccountIntervention(anyString(), any()))
                .thenReturn(
                        new AccountIntervention(
                                new AccountInterventionState(false, false, false, false)));
        when(ipvCallbackHelper.generateAuthenticationErrorResponse(
                        any(), any(), anyBoolean(), anyString(), anyString()))
                .thenReturn(
                        generateApiGatewayProxyResponse(
                                302,
                                "",
                                Map.of(ResponseHeaders.LOCATION, accessDeniedURI.toString()),
                                null));
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenIdentityIsNotEnabled()
            throws UnsuccessfulCredentialResponseException {
        when(configService.isIdentityEnabled()).thenReturn(false);
        usingValidSession();
        usingValidClientSession();

        var request = getApiGatewayProxyRequestEvent(null, clientRegistry);
        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldMakeAISCallAndReturnAccessDeniedErrorToRPWhenP0()
            throws UnsuccessfulCredentialResponseException, IpvCallbackException {
        usingValidSession();
        usingValidClientSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P0",
                                        "vtm", OIDC_BASE_URL + "/trustmark")));

        when(ipvCallbackHelper.validateUserIdentityResponse(any(UserInfo.class), eq(VTR_LIST)))
                .thenReturn(Optional.of(OAuth2Error.ACCESS_DENIED));
        when(configService.isAccountInterventionServiceActionEnabled()).thenReturn(false);

        var response =
                makeHandlerRequest(
                        getApiGatewayProxyRequestEvent(userIdentityUserInfo, clientRegistry));

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));
        var expectedInternalPairwiseSubjectId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                userProfile, configService.getInternalSectorURI(), dynamoService)
                        .getValue();
        verify(accountInterventionService)
                .getAccountIntervention(
                        eq(expectedInternalPairwiseSubjectId), any(AuditContext.class));
    }

    @ParameterizedTest
    @MethodSource("returnCodeClaims")
    void shouldReturnAccessDeniedToRPIfReturnCodePresentButNotPermittedAndRequested(
            ClientRegistry clientRegistry, OIDCClaimsRequest claimsRequest, URI expectedURI)
            throws UnsuccessfulCredentialResponseException,
                    IpvCallbackException,
                    UserNotFoundException {
        usingValidSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub",
                                        "sub-val",
                                        "vot",
                                        "P0",
                                        "vtm",
                                        OIDC_BASE_URL + "/trustmark",
                                        "https://vocab.account.gov.uk/v1/returnCode",
                                        List.of(Map.of("code", "A")))));
        when(ipvCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo, VTR_LIST))
                .thenReturn(Optional.of(OAuth2Error.ACCESS_DENIED));
        when(ipvCallbackHelper.generateReturnCodeAuthenticationResponse(
                        any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
                        any(), any()))
                .thenReturn(
                        new AuthenticationSuccessResponse(
                                REDIRECT_URI, null, null, null, null, null, null));
        var clientSession =
                new ClientSession(
                        generateAuthRequest(claimsRequest).toParameters(),
                        null,
                        List.of(
                                new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                                new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL)),
                        CLIENT_NAME);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));

        var response =
                makeHandlerRequest(
                        getApiGatewayProxyRequestEvent(userIdentityUserInfo, clientRegistry));

        assertThat(response, hasStatus(302));
        assertEquals(expectedURI.toString(), response.getHeaders().get(ResponseHeaders.LOCATION));
    }

    @Nested
    class SetIsNewAccountInOrchSessionFeatureFlag {
        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldCallHelperWithFeatureFlag(boolean isFlagEnabled)
                throws UnsuccessfulCredentialResponseException,
                        IpvCallbackException,
                        UserNotFoundException {
            usingValidSession();
            var claimsSetRequest =
                    new ClaimsSetRequest()
                            .add(ValidClaims.ADDRESS.getValue())
                            .add(ValidClaims.PASSPORT.getValue())
                            .add(ValidClaims.CORE_IDENTITY_JWT.getValue());

            var oidcValidClaimsRequestWithoutReturnCode =
                    new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);

            var expectedURI =
                    new AuthenticationErrorResponse(
                                    URI.create(REDIRECT_URI.toString()),
                                    OAuth2Error.ACCESS_DENIED,
                                    RP_STATE,
                                    null)
                            .toURI();

            var userIdentityUserInfo =
                    new UserInfo(
                            new JSONObject(
                                    Map.of(
                                            "sub",
                                            "sub-val",
                                            "vot",
                                            "P0",
                                            "vtm",
                                            OIDC_BASE_URL + "/trustmark",
                                            "https://vocab.account.gov.uk/v1/returnCode",
                                            List.of(Map.of("code", "A")))));
            when(ipvCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo, VTR_LIST))
                    .thenReturn(Optional.of(OAuth2Error.ACCESS_DENIED));
            when(ipvCallbackHelper.generateReturnCodeAuthenticationResponse(
                            any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
                            any(), any(), any()))
                    .thenReturn(
                            new AuthenticationSuccessResponse(
                                    REDIRECT_URI, null, null, null, null, null, null));
            var clientSession =
                    new ClientSession(
                            generateAuthRequest(oidcValidClaimsRequestWithoutReturnCode)
                                    .toParameters(),
                            null,
                            List.of(
                                    new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                                    new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL)),
                            CLIENT_NAME);
            when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(clientSession));

            var response =
                    makeHandlerRequest(
                            getApiGatewayProxyRequestEvent(
                                    userIdentityUserInfo, generateClientRegistryNoClaims()));

            assertThat(response, hasStatus(302));
            assertEquals(
                    expectedURI.toString(), response.getHeaders().get(ResponseHeaders.LOCATION));
        }
    }

    @Test
    void shouldReturnAuthCodeToRPWhenP0AndReturnCodePresentPermittedAndRequested()
            throws UnsuccessfulCredentialResponseException,
                    IpvCallbackException,
                    UserNotFoundException {
        usingValidSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub",
                                        "sub-val",
                                        "vot",
                                        "P0",
                                        "vtm",
                                        OIDC_BASE_URL + "/trustmark",
                                        IdentityClaims.CORE_IDENTITY.getValue(),
                                        CORE_IDENTITY_CLAIM,
                                        IdentityClaims.CREDENTIAL_JWT.getValue(),
                                        CREDENTIAL_JWT_CLAIM,
                                        ValidClaims.RETURN_CODE.getValue(),
                                        List.of(Map.of("code", "Z")))));
        var clientRegistry =
                generateClientRegistryNoClaims()
                        .withClaims(
                                List.of(
                                        "https://vocab.account.gov.uk/v1/coreIdentityJWT",
                                        "https://vocab.account.gov.uk/v1/returnCode"));
        var claimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(ValidClaims.ADDRESS.getValue())
                                        .add(ValidClaims.PASSPORT.getValue())
                                        .add(ValidClaims.CORE_IDENTITY_JWT.getValue())
                                        .add(ValidClaims.RETURN_CODE.getValue()));
        var clientSession =
                new ClientSession(
                        generateAuthRequest(claimsRequest).toParameters(),
                        null,
                        (List<VectorOfTrust>) EMPTY_LIST,
                        CLIENT_NAME);

        when(responseService.validateResponse(anyMap(), anyString())).thenReturn(Optional.empty());
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
        when(ipvCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo, VTR_LIST))
                .thenReturn(Optional.of(OAuth2Error.ACCESS_DENIED));
        when(ipvCallbackHelper.generateReturnCodeAuthenticationResponse(
                        any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
                        any(), any()))
                .thenReturn(
                        new AuthenticationSuccessResponse(
                                FRONT_END_IPV_CALLBACK_URI, null, null, null, null, null, null));

        var response =
                makeHandlerRequest(
                        getApiGatewayProxyRequestEvent(userIdentityUserInfo, clientRegistry));

        assertDoesRedirectToFrontendPage(response, FRONT_END_IPV_CALLBACK_URI);
    }

    @Test
    void shouldNotInvokeSPOTAndReturnAccessDeniedErrorToRPWhenP0()
            throws UnsuccessfulCredentialResponseException, IpvCallbackException {
        usingValidSession();
        usingValidClientSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P0",
                                        "vtm", OIDC_BASE_URL + "/trustmark")));
        when(ipvCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo, VTR_LIST))
                .thenReturn(Optional.of(OAuth2Error.ACCESS_DENIED));

        var response =
                makeHandlerRequest(
                        getApiGatewayProxyRequestEvent(userIdentityUserInfo, clientRegistry));

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));

        verifyNoInteractions(dynamoIdentityService);
        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyNoInteractions(awsSqsClient);
    }

    @ParameterizedTest
    @MethodSource("additionalClaims")
    void shouldInvokeSPOTAndRedirectToFrontendCallbackForSuccessfulResponseAtP2(
            Map<String, String> additionalClaims)
            throws Json.JsonException, UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        Map<String, Object> userIdentityAdditionalClaims = new HashMap<>();

        for (var entry : additionalClaims.entrySet()) {
            userIdentityAdditionalClaims.put(
                    entry.getKey(), objectMapper.readValue(entry.getValue(), JSONArray.class));
        }

        var claims =
                new HashMap<String, Object>(
                        Map.of(
                                "sub",
                                "sub-val",
                                "vot",
                                "P2",
                                "vtm",
                                OIDC_BASE_URL + "/trustmark",
                                IdentityClaims.CORE_IDENTITY.getValue(),
                                CORE_IDENTITY_CLAIM,
                                IdentityClaims.CREDENTIAL_JWT.getValue(),
                                CREDENTIAL_JWT_CLAIM));
        claims.putAll(userIdentityAdditionalClaims);

        var response =
                makeHandlerRequest(
                        getApiGatewayProxyRequestEvent(
                                new UserInfo(new JSONObject(claims)), clientRegistry));

        assertDoesRedirectToFrontendPage(response, FRONT_END_IPV_CALLBACK_URI);
        var expectedRpPairwiseSub =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry, dynamoService, INTERNAL_SECTOR_URI);
        verify(ipvCallbackHelper)
                .queueSPOTRequest(
                        any(),
                        anyString(),
                        eq(userProfile),
                        eq(expectedRpPairwiseSub),
                        any(UserInfo.class),
                        eq(CLIENT_ID.getValue()));
        verify(ipvCallbackHelper)
                .saveIdentityClaimsToDynamo(any(Subject.class), any(UserInfo.class));

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED);
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldNotInvokeSPOTAndShouldRedirectToFrontendErrorPageWhenVTMMismatch()
            throws UnsuccessfulCredentialResponseException, IpvCallbackException {
        usingValidSession();
        usingValidClientSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P2",
                                        "vtm", OIDC_BASE_URL + "/invalid-trustmark")));
        doThrow(new IpvCallbackException("IPV trustmark is invalid"))
                .when(ipvCallbackHelper)
                .validateUserIdentityResponse(userIdentityUserInfo, VTR_LIST);

        var request = getApiGatewayProxyRequestEvent(userIdentityUserInfo, clientRegistry);

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(awsSqsClient);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenSessionIsNotFoundInRedis() {
        var request = new APIGatewayProxyRequestEvent();
        request.setQueryStringParameters(Collections.emptyMap());
        request.setHeaders(Map.of(COOKIE, buildCookieString()));

        when(sessionService.getSession(SESSION_ID)).thenReturn(Optional.empty());

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_IPV_CALLBACK_ERROR_URI);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenOrchSessionIsNotFound() {
        var request = new APIGatewayProxyRequestEvent();
        request.setQueryStringParameters(Collections.emptyMap());
        request.setHeaders(Map.of(COOKIE, buildCookieString()));

        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.empty());

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_IPV_CALLBACK_ERROR_URI);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenUserProfileNotFound() {
        usingValidSession();
        usingValidClientSession();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistryNoClaims()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.setQueryStringParameters(responseHeaders);
        request.setHeaders(Map.of(COOKIE, buildCookieString()));

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenUserIdentityRequestFails()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        var claims =
                new HashMap<String, Object>(
                        Map.of(
                                "sub",
                                "sub-val",
                                "vot",
                                "P2",
                                "vtm",
                                OIDC_BASE_URL + "/trustmark",
                                IdentityClaims.CORE_IDENTITY.getValue(),
                                CORE_IDENTITY_CLAIM,
                                IdentityClaims.CREDENTIAL_JWT.getValue(),
                                CREDENTIAL_JWT_CLAIM));

        var request =
                getApiGatewayProxyRequestEvent(
                        new UserInfo(new JSONObject(claims)), clientRegistry);

        doThrow(
                        new UnsuccessfulCredentialResponseException(
                                "Error when attempting to parse http response to UserInfoResponse"))
                .when(ipvTokenService)
                .sendIpvUserIdentityRequest(any(UserInfoRequest.class));

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);
    }

    @Test
    void shouldMakeAISCallBeforeRedirectingToRpWhenAuthResponseContainsError() {
        usingValidSession();
        usingValidClientSession();
        var errorObject = new ErrorObject("invalid_request_redirect_uri", redirectUriErrorMessage);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistryNoClaims()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(
                        Optional.of(
                                new ErrorObject(errorObject.getCode(), redirectUriErrorMessage)));
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        var response = handler.handleRequest(event, context);

        var expectedInternalPairwiseSubjectId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                userProfile, configService.getInternalSectorURI(), dynamoService)
                        .getValue();

        assertThat(response, hasStatus(302));
        assertEquals(
                accessDeniedURI.toString(), response.getHeaders().get(ResponseHeaders.LOCATION));
        verify(accountInterventionService)
                .getAccountIntervention(
                        eq(expectedInternalPairwiseSubjectId), any(AuditContext.class));

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToRpWhenAuthResponseContainsError() {
        usingValidSession();
        usingValidClientSession();
        var errorObject = new ErrorObject("invalid_request_redirect_uri", redirectUriErrorMessage);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistryNoClaims()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(
                        Optional.of(
                                new ErrorObject(errorObject.getCode(), redirectUriErrorMessage)));
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        var response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertEquals(
                accessDeniedURI.toString(), response.getHeaders().get(ResponseHeaders.LOCATION));
        verify(ipvCallbackHelper)
                .generateAuthenticationErrorResponse(
                        any(), any(), anyBoolean(), anyString(), anyString());

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenClientSessionIsNotFound() {
        usingValidSession();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.setHeaders(Map.of(COOKIE, buildCookieString()));
        request.setQueryStringParameters(responseHeaders);

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_IPV_CALLBACK_ERROR_URI);

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenClientRegistryIsNotFound()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        var request = getApiGatewayProxyRequestEvent(null, clientRegistry);

        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenTokenResponseIsNotSuccessful() {
        var salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes(StandardCharsets.UTF_8);
        var clientRegistry = generateClientRegistryNoClaims();
        var userProfile = generateUserProfile();
        usingValidSession();
        usingValidClientSession();
        var unsuccessfulTokenResponse =
                new TokenErrorResponse(new ErrorObject("Test error response"));
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(ipvTokenService.getToken(AUTH_CODE.getValue())).thenReturn(unsuccessfulTokenResponse);

        var request = new APIGatewayProxyRequestEvent();
        request.setQueryStringParameters(responseHeaders);
        request.setHeaders(Map.of(COOKIE, buildCookieString()));

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToFrontendPage(response, FRONT_END_ERROR_URI);

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws NoSessionException {
        usingValidSession();
        usingValidClientSession();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("state", STATE.getValue());
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        when(noSessionOrchestrationService.generateNoSessionOrchestrationEntity(queryParameters))
                .thenReturn(
                        new NoSessionEntity(
                                CLIENT_SESSION_ID, OAuth2Error.ACCESS_DENIED, clientSession));

        var response =
                handler.handleRequest(
                        new APIGatewayProxyRequestEvent()
                                .withQueryStringParameters(queryParameters),
                        context);

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));
        verify(ipvCallbackHelper)
                .generateAuthenticationErrorResponse(
                        any(), any(), anyBoolean(), anyString(), anyString());
        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButCallToNoSessionOrchestrationServiceThrowsException()
                    throws NoSessionException {
        usingValidSession();
        usingValidClientSession();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("state", STATE.getValue());

        doThrow(
                        new NoSessionException(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false"))
                .when(noSessionOrchestrationService)
                .generateNoSessionOrchestrationEntity(queryParameters);

        var response =
                handler.handleRequest(
                        new APIGatewayProxyRequestEvent()
                                .withQueryStringParameters(queryParameters),
                        context);

        assertDoesRedirectToFrontendPage(response, FRONT_END_IPV_CALLBACK_ERROR_URI);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false")));

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @ParameterizedTest
    @MethodSource("getFrontendCases")
    void getFrontendShouldReturnCorrectFrontendDependingOnValueOfOrchFrontendEnabledFlag(
            boolean orchFrontendEnabled, Class<? extends CommonFrontend> expectedFrontendClass) {
        var configurationService = mock(ConfigurationService.class);
        when(configurationService.getOrchFrontendEnabled()).thenReturn(orchFrontendEnabled);
        var actualFrontendClass = IPVCallbackHandler.getFrontend(configurationService).getClass();
        assertThat(actualFrontendClass, is(equalTo(expectedFrontendClass)));
    }

    @Test
    void shouldLogoutUserWhenAISReturnsBlockedAccountInAuthStep() {
        usingValidSession();
        usingValidClientSession();
        var errorObject = new ErrorObject("invalid_request_redirect_uri", redirectUriErrorMessage);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistryNoClaims()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(
                        Optional.of(
                                new ErrorObject(errorObject.getCode(), redirectUriErrorMessage)));
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        var intervention =
                new AccountIntervention(new AccountInterventionState(true, false, false, false));
        when(accountInterventionService.getAccountIntervention(anyString(), any()))
                .thenReturn(intervention);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);
        handler.handleRequest(event, context);

        verify(logoutService)
                .handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(), TEST_EMAIL_ADDRESS),
                        TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER,
                        event,
                        CLIENT_ID.getValue(),
                        intervention);
    }

    @Test
    void shouldLogoutUserWhenAISReturnsBlockedAccountInTokenStep() throws IpvCallbackException {
        var salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes(StandardCharsets.UTF_8);
        var clientRegistry = generateClientRegistryNoClaims();
        var userProfile = generateUserProfile();
        usingValidSession();
        usingValidClientSession();
        when(ipvCallbackHelper.validateUserIdentityResponse(any(), eq(VTR_LIST)))
                .thenReturn(Optional.of(OAuth2Error.ACCESS_DENIED));
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        var successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        when(ipvTokenService.getToken(AUTH_CODE.getValue())).thenReturn(successfulTokenResponse);
        var intervention =
                new AccountIntervention(new AccountInterventionState(true, false, false, false));
        when(accountInterventionService.getAccountIntervention(anyString(), any()))
                .thenReturn(intervention);

        var request = new APIGatewayProxyRequestEvent();
        request.setQueryStringParameters(responseHeaders);
        request.setHeaders(Map.of(COOKIE, buildCookieString()));

        handler.handleRequest(request, context);

        verify(logoutService)
                .handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(), TEST_EMAIL_ADDRESS),
                        TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER,
                        request,
                        CLIENT_ID.getValue(),
                        intervention);
    }

    static Stream<Arguments> getFrontendCases() {
        return Stream.of(
                Arguments.of(true, OrchFrontend.class), Arguments.of(false, AuthFrontend.class));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        return handler.handleRequest(event, context);
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s di-persistent-session-id=%s; Max-Age=34190000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                "gs",
                SESSION_ID,
                CLIENT_SESSION_ID,
                3600,
                "Secure; HttpOnly;",
                PERSISTENT_SESSION_ID);
    }

    private void usingValidSession() {
        when(sessionService.getSession(SESSION_ID)).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.of(orchSession));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(TEST_EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPhoneNumber("012345678902")
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(PUBLIC_SUBJECT.getValue())
                .withSubjectID(TEST_SUBJECT.getValue());
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
                .build();
    }

    private void verifyAuditEvent(IPVAuditableEvent auditableEvent) {
        verify(auditService)
                .submitAuditEvent(
                        auditableEvent,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withSessionId(SESSION_ID)
                                .withUserId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER)
                                .withEmail(TEST_EMAIL_ADDRESS)
                                .withPhone(userProfile.getPhoneNumber())
                                .withPersistentSessionId(PERSISTENT_SESSION_ID));
    }

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(
            UserInfo userIdentityUserInfo, ClientRegistry clientRegistry)
            throws UnsuccessfulCredentialResponseException {
        var successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);

        when(ipvTokenService.getToken(AUTH_CODE.getValue())).thenReturn(successfulTokenResponse);
        when(ipvTokenService.sendIpvUserIdentityRequest(any())).thenReturn(userIdentityUserInfo);

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
    }

    private void assertDoesRedirectToFrontendPage(
            APIGatewayProxyResponseEvent response, URI frontEndPage) {
        assertThat(response, hasStatus(302));
        var expectedRedirectURI = frontEndPage;
        assertEquals(expectedRedirectURI.toString(), response.getHeaders().get("Location"));
    }
}
