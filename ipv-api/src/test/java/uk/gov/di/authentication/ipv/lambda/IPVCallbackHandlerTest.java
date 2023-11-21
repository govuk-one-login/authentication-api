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
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTClaims;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.IdentityClaims;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.NoSessionEntity;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.exceptions.NoSessionException;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NoSessionOrchestrationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.CORE_IDENTITY_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.CREDENTIAL_JWT_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerTest {
    private static final Subject SUBJECT = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final IPVAuthorisationService responseService = mock(IPVAuthorisationService.class);
    private final IPVTokenService ipvTokenService = mock(IPVTokenService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final CookieHelper cookieHelper = mock(CookieHelper.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String OIDC_BASE_URL = "https://base-url.com";
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
    private IPVCallbackHandler handler;
    private final byte[] salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes();
    private final ClientRegistry clientRegistry = generateClientRegistry();
    private final UserProfile userProfile = generateUserProfile();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), "test.account.gov.uk", SaltHelper.generateNewSalt());

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(IPVCallbackHandler.class);

    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);

    private final ClientSession clientSession =
            new ClientSession(generateAuthRequest().toParameters(), null, null, CLIENT_NAME);

    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        handler =
                new IPVCallbackHandler(
                        configService,
                        responseService,
                        ipvTokenService,
                        sessionService,
                        dynamoService,
                        clientSessionService,
                        dynamoClientService,
                        auditService,
                        awsSqsClient,
                        dynamoIdentityService,
                        cookieHelper,
                        noSessionOrchestrationService);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URL));
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.isIdentityEnabled()).thenReturn(true);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(cookieHelper.parseSessionCookie(anyMap())).thenCallRealMethod();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenIdentityIsNotEnabled()
            throws URISyntaxException, UnsuccessfulCredentialResponseException {
        when(configService.isIdentityEnabled()).thenReturn(false);
        usingValidSession();
        usingValidClientSession();

        var event = getApiGatewayProxyRequestEvent(null);

        assertDoesRedirectToFrontendErrorPage(event, "error");

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldNotInvokeSPOTAndReturnAccessDeniedErrorToRPWhenP0()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P0",
                                        "vtm", OIDC_BASE_URL + "/trustmark")));

        var response = makeHandlerRequest(getApiGatewayProxyRequestEvent(userIdentityUserInfo));
        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));

        verifyNoInteractions(dynamoIdentityService);
        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyNoInteractions(awsSqsClient);
    }

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

    @ParameterizedTest
    @MethodSource("additionalClaims")
    void shouldInvokeSPOTAndRedirectToFrontendCallbackForSuccessfulResponseAtP2(
            Map<String, String> additionalClaims)
            throws URISyntaxException, Json.JsonException, UnsuccessfulCredentialResponseException {
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
                        getApiGatewayProxyRequestEvent(new UserInfo(new JSONObject(claims))));

        assertThat(response, hasStatus(302));
        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath("ipv-callback").build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        var expectedPairwiseSub =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry, dynamoService, INTERNAL_SECTOR_URI);
        verify(awsSqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new SPOTRequest(
                                        SPOTClaims.builder()
                                                .withVot(LevelOfConfidence.MEDIUM_LEVEL.getValue())
                                                .withVtm(OIDC_BASE_URL + "/trustmark")
                                                .withClaim(
                                                        IdentityClaims.CORE_IDENTITY.getValue(),
                                                        CORE_IDENTITY_CLAIM)
                                                .withClaim(
                                                        IdentityClaims.CREDENTIAL_JWT.getValue(),
                                                        CREDENTIAL_JWT_CLAIM)
                                                .build(),
                                        SUBJECT.getValue(),
                                        salt,
                                        "test.com",
                                        expectedPairwiseSub.getValue(),
                                        new LogIds(
                                                session.getSessionId(),
                                                PERSISTENT_SESSION_ID,
                                                REQUEST_ID,
                                                CLIENT_ID.getValue(),
                                                CLIENT_SESSION_ID),
                                        CLIENT_ID.getValue())));

        verify(dynamoIdentityService)
                .saveIdentityClaims(
                        expectedPairwiseSub.getValue(),
                        additionalClaims,
                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                        CORE_IDENTITY_CLAIM);
        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED);
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldNotInvokeSPOTAndShouldRedirectToFrontendErrorPageWhenVTMMismatch()
            throws URISyntaxException, UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();
        var userIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P2",
                                        "vtm", OIDC_BASE_URL + "/invalid-trustmark")));

        var event = getApiGatewayProxyRequestEvent(userIdentityUserInfo);

        assertDoesRedirectToFrontendErrorPage(event, "error");

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(awsSqsClient);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenSessionIsNotFoundInRedis() throws URISyntaxException {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.empty());

        assertDoesRedirectToFrontendErrorPage(event, "ipv-callback-session-expiry-error");
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenUserProfileNotFound() throws URISyntaxException {
        usingValidSession();
        usingValidClientSession();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        assertDoesRedirectToFrontendErrorPage(event, "error");

        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenUserIdentityRequestFails()
            throws URISyntaxException, UnsuccessfulCredentialResponseException {
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

        var event = getApiGatewayProxyRequestEvent(new UserInfo(new JSONObject(claims)));

        doThrow(
                        new UnsuccessfulCredentialResponseException(
                                "Error when attempting to parse http response to UserInfoResponse"))
                .when(ipvTokenService)
                .sendIpvUserIdentityRequest(any(UserInfoRequest.class));
        assertDoesRedirectToFrontendErrorPage(event, "error");
    }

    @Test
    void shouldRedirectToRpWhenAuthResponseContainsError() {
        var errorDescription = "redirect_uri param must be provided";
        usingValidSession();
        usingValidClientSession();
        var errorObject = new ErrorObject("invalid_request_redirect_uri", errorDescription);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.of(new ErrorObject(errorObject.getCode(), errorDescription)));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        var response = handler.handleRequest(event, context);

        var expectedErrorObject = new ErrorObject(OAuth2Error.ACCESS_DENIED_CODE, errorDescription);
        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                expectedErrorObject,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));
        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenClientSessionIsNotFound() throws URISyntaxException {
        usingValidSession();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        assertDoesRedirectToFrontendErrorPage(event, "ipv-callback-session-expiry-error");

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenClientRegistryIsNotFound()
            throws URISyntaxException, UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        var event = getApiGatewayProxyRequestEvent(null);

        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

        assertDoesRedirectToFrontendErrorPage(event, "error");

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenTokenResponseIsNotSuccessful()
            throws URISyntaxException {
        var salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes();
        var clientRegistry = generateClientRegistry();
        var userProfile = generateUserProfile();
        usingValidSession();
        usingValidClientSession();
        var unsuccessfulTokenResponse =
                new TokenErrorResponse(new ErrorObject("Test error response"));
        var tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(ipvTokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(ipvTokenService.sendTokenRequest(tokenRequest)).thenReturn(unsuccessfulTokenResponse);

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));

        assertDoesRedirectToFrontendErrorPage(event, "error");

        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        PERSISTENT_SESSION_ID);

        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        PERSISTENT_SESSION_ID);

        verifyNoMoreInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws NoSessionException {
        usingValidSession();
        usingValidClientSession();
        when(configService.isIPVNoSessionResponseEnabled()).thenReturn(true);

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("state", STATE.getValue());
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        when(noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                        queryParameters, true))
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
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));
        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(dynamoIdentityService);
        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                        CLIENT_SESSION_ID,
                        AuditService.UNKNOWN,
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButCallToNoSessionOrchestrationServiceThrowsException()
                    throws NoSessionException, URISyntaxException {
        usingValidSession();
        usingValidClientSession();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("state", STATE.getValue());

        doThrow(
                        new NoSessionException(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false"))
                .when(noSessionOrchestrationService)
                .generateNoSessionOrchestrationEntity(queryParameters, false);

        var response =
                handler.handleRequest(
                        new APIGatewayProxyRequestEvent()
                                .withQueryStringParameters(queryParameters),
                        context);

        var expectedRedirectURI =
                new URIBuilder(LOGIN_URL).setPath("ipv-callback-session-expiry-error").build();
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false")));

        verifyNoInteractions(ipvTokenService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoIdentityService);
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
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
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
                .withSubjectID(SUBJECT.getValue());
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withConsentRequired(false)
                .withClientName("test-client")
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise");
    }

    public static AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(nonce)
                .build();
    }

    private void verifyAuditEvent(IPVAuditableEvent auditableEvent) {
        verify(auditService)
                .submitAuditEvent(
                        auditableEvent,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        PERSISTENT_SESSION_ID);
    }

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(
            UserInfo userIdentityUserInfo) throws UnsuccessfulCredentialResponseException {
        var successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        var tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(ipvTokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(ipvTokenService.sendTokenRequest(tokenRequest)).thenReturn(successfulTokenResponse);
        when(ipvTokenService.sendIpvUserIdentityRequest(any())).thenReturn(userIdentityUserInfo);

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
    }

    private void assertDoesRedirectToFrontendErrorPage(
            APIGatewayProxyRequestEvent event, String errorPagePath) throws URISyntaxException {
        var response = handler.handleRequest(event, context);
        assertThat(response, hasStatus(302));

        var expectedRedirectURI = new URIBuilder(LOGIN_URL).setPath(errorPagePath).build();
        assertThat(response.getHeaders().get("Location"), equalTo(expectedRedirectURI.toString()));
    }
}
