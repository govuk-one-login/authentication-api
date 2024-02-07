package uk.gov.di.authentication.ipv.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonBody;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.core5.net.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.helpers.IPVCallbackHelper;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.shared.entity.*;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.*;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.*;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.*;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;

@PactConsumerTest
public class IpvUserIdentityTest {
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
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private final LogoutService logoutService = mock(LogoutService.class);
    private final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private final IPVCallbackHelper ipvCallbackHelper = mock(IPVCallbackHelper.class);
    private final AuditService auditService = mock(AuditService.class);

    private final Json objectMapper = SerializationService.getInstance();

    private IPVCallbackHandler handler;

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
    private final byte[] salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes();
    private final ClientRegistry clientRegistry = generateClientRegistry();
    private final UserProfile userProfile = generateUserProfile();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), "test.account.gov.uk", salt);

    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String OIDC_BASE_URL = "https://base-url.com";
    private static final String IPV_USER_IDENTITY_PATH = "user-identity";

    private static final Map<String, String> additionalClaims =
            Map.of(
                    ValidClaims.ADDRESS.getValue(),
                    ADDRESS_CLAIM,
                    ValidClaims.PASSPORT.getValue(),
                    PASSPORT_CLAIM);

    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);

    private final ClientSession clientSession =
            new ClientSession(
                            generateAuthRequest(new OIDCClaimsRequest()).toParameters(),
                            null,
                            new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                            CLIENT_NAME)
                    .setEffectiveVectorOfTrust(
                            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL));

    private AccessToken accessToken;

    private final String SUB_FIELD = "sub";
    private final String VOT_FIELD = "vot";
    private final String VTM_FIELD = "vtm";
    private final String CREDENTIALS_JWT_FIELD = "https://vocab.account.gov.uk/v1/credentialJWT";
    private final String CORE_IDENTITY_FIELD = "https://vocab.account.gov.uk/v1/coreIdentity";
    private final String CORE_IDENTITY_NAME_FIELD = "name";
    private final String CORE_IDENTITY_NAME_PARTS_FIELD = "nameParts";
    private final String CORE_IDENTITY_BIRTH_FIELD = "birthDate";

    private final String SUB_VALUE = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private final String VOT_VALUE = "P2";
    private final String VTM_VALUE = "http://localhost/trustmark";
    private final String CREDENTIALS_JWT_VALUE = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
    private final String CORE_IDENTITY_BIRTH_VALUE = "1964-11-07";

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
                        logoutService,
                        accountInterventionService,
                        cookieHelper,
                        noSessionOrchestrationService,
                        ipvCallbackHelper);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URL));
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.isIdentityEnabled()).thenReturn(true);
        when(configService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(cookieHelper.parseSessionCookie(anyMap())).thenCallRealMethod();
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
        accessToken = new Tokens(new BearerAccessToken(), null).getAccessToken();
    }

    @Pact(consumer = "IPV-orch-user-identity-consumer")
    RequestResponsePact success(PactDslWithProvider builder) {
        return builder.given("send user identity request to IPV")
                .uponReceiving("user identity request")
                .path("/" + IPV_USER_IDENTITY_PATH)
                .method("GET")
                .matchHeader("Authorization", accessToken.toAuthorizationHeader())
                .willRespondWith()
                .status(200)
                .body(
                        new PactDslJsonBody()
                                .stringType(SUB_FIELD, SUB_VALUE)
                                .stringType(VOT_FIELD, VOT_VALUE)
                                .stringType(VTM_FIELD, VTM_VALUE)
                                .unorderedMaxArray(CREDENTIALS_JWT_FIELD, 1)
                                .stringType(CREDENTIALS_JWT_VALUE)
                                .closeArray()
                                .object(CORE_IDENTITY_FIELD)
                                .maxArrayLike(CORE_IDENTITY_NAME_FIELD, 1)
                                .eachLike(CORE_IDENTITY_NAME_PARTS_FIELD, 2)
                                .stringType("type", "Name")
                                .stringType("value", "Kenneth")
                                .closeObject()
                                .closeArray()
                                .closeObject()
                                .closeArray()
                                .maxArrayLike(CORE_IDENTITY_BIRTH_FIELD, 1)
                                .stringType("value", CORE_IDENTITY_BIRTH_VALUE)
                                .closeArray()
                                .closeObject())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IPV-orch-user-identity-provider",
            pactMethod = "success",
            pactVersion = PactSpecVersion.V3)
    void getIPVResponse(MockServer mockServer)
            throws IOException,
                    Json.JsonException,
                    UnsuccessfulCredentialResponseException,
                    URISyntaxException,
                    ParseException {
        URIBuilder builder = new URIBuilder(mockServer.getUrl() + "/" + IPV_USER_IDENTITY_PATH);
        Request.get(builder.build())
                .addHeader("Authorization", accessToken.toAuthorizationHeader())
                .execute();

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

        handler.handleRequest(getApiGatewayProxyRequestEvent(), context);

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED);
    }

    private void usingValidSession() {
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
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

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent()
            throws UnsuccessfulCredentialResponseException, ParseException {
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
        when(ipvTokenService.sendIpvUserIdentityRequest(any()))
                .thenReturn(getUserInfoFromSuccessfulUserIdentityHttpResponse());

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
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

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(TEST_EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPhoneNumber("012345678902")
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(PUBLIC_SUBJECT.getValue())
                .withSubjectID(SUBJECT.getValue());
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
                .build();
    }

    private UserInfo getUserInfoFromSuccessfulUserIdentityHttpResponse() throws ParseException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(
                "{"
                        + " \""
                        + SUB_FIELD
                        + "\": \""
                        + SUB_VALUE
                        + "\","
                        + " \""
                        + VOT_FIELD
                        + "\": \""
                        + VOT_VALUE
                        + "\","
                        + " \""
                        + VTM_FIELD
                        + "\": \""
                        + VTM_FIELD
                        + "\","
                        + " \""
                        + CREDENTIALS_JWT_FIELD
                        + "\": ["
                        + "     \""
                        + CREDENTIALS_JWT_VALUE
                        + "\""
                        + "],"
                        + " \""
                        + CORE_IDENTITY_FIELD
                        + "\": {"
                        + "     \""
                        + CORE_IDENTITY_NAME_FIELD
                        + "\": ["
                        + "         { \""
                        + CORE_IDENTITY_NAME_PARTS_FIELD
                        + "\": ["
                        + "         { \"value\":\"GivenName\",\"value\":\"kenneth\" } "
                        + "         ] "
                        + "     } "
                        + "     ],"
                        + "     \""
                        + CORE_IDENTITY_BIRTH_FIELD
                        + "\": [ "
                        + "         { \"value\": \""
                        + CORE_IDENTITY_BIRTH_VALUE
                        + "\" } "
                        + "     ]"
                        + " }"
                        + "}");
        var userIdentityResponse = UserInfoResponse.parse(userInfoHTTPResponse);
        return userIdentityResponse.toSuccessResponse().getUserInfo();
    }
}
