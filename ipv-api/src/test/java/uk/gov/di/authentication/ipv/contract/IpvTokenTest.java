package uk.gov.di.authentication.ipv.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonBody;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.helpers.IPVCallbackHelper;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.shared.entity.*;
import uk.gov.di.orchestration.shared.helpers.*;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.*;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
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
@MockServerConfig(hostInterface = "localHost", port="1234")
public class IpvTokenTest {
    private static final Subject SUBJECT = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final IPVAuthorisationService responseService = mock(IPVAuthorisationService.class);
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
    private final IPVTokenService ipvTokenService = new IPVTokenService(configService, kmsConnectionService);

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
    private static final ClientID CLIENT_ID = new ClientID("authOrchestrator");
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
    private static final String IPV_TOKEN_PATH = "token";
    private static final URI IPV_TOKEN_URI =
            ConstructUriHelper.buildURI("https://api.identity.account.gov.uk", IPV_TOKEN_PATH);
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
                    List.of(
                            new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL)),
                    CLIENT_NAME);

    private final String ACCESS_TOKEN_FIELD = "access_token";
    private final String TOKEN_TYPE_FIELD = "token_type";
    private final String EXPIRES_IN_FIELD = "expires_in";
    private final String URI_FIELD = "uri";
    private final String ACCESS_TOKEN_VALUE = "740e5834-3a29-46b4-9a6f-16142fde533a";
    private final String TOKEN_TYPE_VALUE = "bearer";
    private final String EXPIRES_IN_VALUE = "3600";
    private final String URI_VALUE = "https://localhost";
    private static final String KEY_ID = "14342354354353";

    private static final String PRIVATE_JWT_KEY = "{\"kty\":\"EC\",\"d\":\"A2cfN3vYKgOQ_r1S6PhGHCLLiVEqUshFYExrxMwkq_A\",\"crv\":\"P-256\",\"kid\":\"14342354354353\",\"x\":\"BMyQQqr3NEFYgb9sEo4hRBje_HHEsy87PbNIBGL4Uiw\",\"y\":\"qoXdkYVomy6HWT6yNLqjHSmYoICs6ioUF565Btx0apw\",\"alg\":\"ES256\"}";

    private static final String CLIENT_ASSERTION_HEADER = "eyJraWQiOiIxNDM0MjM1NDM1NDM1MyIsImFsZyI6IkVTMjU2In0";
    private static final String CLIENT_ASSERTION_BODY =
            "eyJzdWIiOiJhdXRoT3JjaGVzdHJhdG9yIiwiYXVkIjoiaHR0cDovL2lwdi8iLCJuYmYiOjk0NjY4NDgwMCwiaXNzIjoiYXV0aE9yY2hlc3RyYXRvciIsImV4cCI6NDA3MDkwODgwMCwiaWF0Ijo5NDY2ODQ4MDAsImp0aSI6IjEifQ";
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "L3h9FCeYLIUCpjMGjnBm6Ca8GmKqICHSGY5Aq0svbMNTmLP04dzh5V8E6N2InzbXC9_4Q7u6mAo3yubbYsVSdA";
    private static final byte[] SIGNATURE_BYTES = {(byte) 48, (byte)68, (byte)2, (byte)32, (byte)47, (byte)120, (byte)125, (byte)20, (byte)39, (byte)-104, (byte)44, (byte)-123, (byte)2, (byte)-90, (byte)51, (byte)6, (byte)-114, (byte)112, (byte)102, (byte)-24, (byte)38, (byte)-68, (byte)26, (byte)98, (byte)-86, (byte)32, (byte)33, (byte)-46, (byte)25, (byte)-114, (byte)64, (byte)-85, (byte)75, (byte)47, (byte)108, (byte)-61, (byte)2, (byte)32, (byte)83, (byte)-104, (byte)-77, (byte)-12, (byte)-31, (byte)-36, (byte)-31, (byte)-27, (byte)95, (byte)4, (byte)-24, (byte)-35, (byte)-120, (byte)-97, (byte)54, (byte)-41, (byte)11, (byte)-33, (byte)-8, (byte)67, (byte)-69, (byte)-70, (byte)-104, (byte)10, (byte)55, (byte)-54, (byte)-26, (byte)-37, (byte)98, (byte)-59, (byte)82, (byte)116};
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
        when(configService.isIdentityEnabled()).thenReturn(true);
        when(configService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(cookieHelper.parseSessionCookie(anyMap())).thenCallRealMethod();
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
    }

    @Pact(consumer = "IPV-orch-token-consumer")
    RequestResponsePact success(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("localHost is a valid resource URI")
                .given("the JWT is signed with " + PRIVATE_JWT_KEY)
                .uponReceiving("token request")
                .path("/" + IPV_TOKEN_PATH)
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&"
                                + "code=dummyAuthCode&"
                                + "grant_type=authorization_code&"
                                + "resource="
                                + "http://localhost:1234/token"
                                + "&"
                                + "client_assertion="
                                + CLIENT_ASSERTION_HEADER
                                + "."
                                + CLIENT_ASSERTION_BODY
                                + "."
                                + CLIENT_ASSERTION_SIGNATURE
                                + "&"
                                + "client_id=" + CLIENT_ID.getValue())
                .headers(
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(200)
                .body(
                        new PactDslJsonBody()
                                .stringType(ACCESS_TOKEN_FIELD, ACCESS_TOKEN_VALUE)
                                .stringType(TOKEN_TYPE_FIELD, TOKEN_TYPE_VALUE)
                                .stringType(EXPIRES_IN_FIELD, EXPIRES_IN_VALUE)
                                .stringType(URI_FIELD, URI_VALUE))
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IPV-orch-token-provider",
            pactMethod = "success",
            pactVersion = PactSpecVersion.V3)
    void getIPVResponse(MockServer mockServer)
            throws Json.JsonException {
        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getIPVBackendURI()).thenReturn(URI.create(mockServer.getUrl()));
        when(configService.getIPVAudience()).thenReturn(IPV_URI.toString());
        when(configService.getIPVTokenSigningKeyAlias()).thenReturn(KEY_ID);

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

        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass.when(NowHelper::now).thenReturn(Date.from(Instant.parse("2000-01-01T00:00:00.00Z")));
            mockedNowHelperClass.when(() -> NowHelper.nowPlus(5L, ChronoUnit.MINUTES)).thenReturn(Date.from(Instant.parse("2099-01-01T00:00:00.00Z")));
            try (var mockJwtId = mockConstruction(JWTID.class, (mock, context) -> {when(mock.getValue()).thenReturn("1");})) {
                handler.handleRequest(
                        getApiGatewayProxyRequestEvent(new UserInfo(new JSONObject(claims))), context);
            };
        }

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        verifyAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED);
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

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(
            UserInfo userIdentityUserInfo) {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", "dummyAuthCode");
        responseHeaders.put("state", STATE.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(dynamoService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(mockKmsReturn());

        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
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

    private SignResponse mockKmsReturn() {
        return SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(SIGNATURE_BYTES))
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .keyId(KEY_ID)
                        .build();
    }

    public HTTPResponse getSuccessfulTokenHttpResponse() throws ParseException {
        var tokenResponseContent =
                "{"
                        + "  \""
                        + ACCESS_TOKEN_FIELD
                        + "\": \""
                        + ACCESS_TOKEN_VALUE
                        + "\","
                        + "  \""
                        + TOKEN_TYPE_FIELD
                        + "\": \""
                        + TOKEN_TYPE_VALUE
                        + "\","
                        + "  \""
                        + EXPIRES_IN_FIELD
                        + "\": \""
                        + EXPIRES_IN_VALUE
                        + "\","
                        + "  \""
                        + URI_FIELD
                        + "\": \""
                        + URI_VALUE
                        + "\""
                        + "}";
        var tokenHTTPResponse = new HTTPResponse(200);
        tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
        tokenHTTPResponse.setContent(tokenResponseContent);

        return tokenHTTPResponse;
    }
}
