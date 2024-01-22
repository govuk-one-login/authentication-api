package uk.gov.di.authentication.ipv.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactBuilder;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.hc.client5.http.fluent.Request;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.helpers.IPVCallbackHelper;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.shared.entity.*;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.*;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.*;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.*;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;

@PactConsumerTest
public class IPVTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final IPVAuthorisationService responseService = mock(IPVAuthorisationService.class);
    private final IPVTokenService ipvTokenService = mock(IPVTokenService.class);
    private final IPVCallbackHelper ipvCallbackHelper = mock(IPVCallbackHelper.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final CookieHelper cookieHelper = mock(CookieHelper.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
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

    private static final Subject SUBJECT = new Subject();
    private static final Subject PUBLIC_SUBJECT =
            new Subject("TsEVC7vg0NPAmzB33vRUFztL2c0-fecKWKcc73fuDhc");
    private static final State STATE = new State();
    private final ClientRegistry clientRegistry = generateClientRegistry();
    private final UserProfile userProfile = generateUserProfile();
    private final byte[] salt = "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), "test.account.gov.uk", salt);

    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String OIDC_BASE_URL = "https://base-url.com";

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
            new ClientSession(generateAuthRequest().toParameters(), null, null, CLIENT_NAME);

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
    }

    @Pact(consumer = "IPV-orch-consumer")
    V4Pact success(PactBuilder builder) {
        return builder.expectsToReceive("request for a IPV", "")
                .with(
                        Map.of(
                                "request.path", "/test_url",
                                "request.status", "200",
                                "request.params", "{key: test}",
                                "response.status", "200",
                                "response.contents",
                                        Map.of(
                                                "pact:content-type", "application/json",
                                                "csvHeaders", false,
                                                "column:1", "matching(type,'Name')",
                                                "column:2", "matching(number,100)",
                                                "column:3",
                                                        "matching(datetime, 'yyyy-MM-dd','2000-01-01')")))
                .toPact();
    }

    @Test
    @PactTestFor(providerName = "IPV-orch-provider", pactMethod = "success")
    void getCsvReport(MockServer mockServer)
            throws IOException, Json.JsonException, UnsuccessfulCredentialResponseException {
        Request.get(mockServer.getUrl() + "/test_url").execute();

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

        handler.handleRequest(
                getApiGatewayProxyRequestEvent(new UserInfo(new JSONObject(claims))), context);

        verifyAuditEvent(IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED);
        //        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        //        verifyAuditEvent(IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        //        verifyAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED);
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
                .withSectorIdentifierUri("https://test.account.gov.uk")
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
}
