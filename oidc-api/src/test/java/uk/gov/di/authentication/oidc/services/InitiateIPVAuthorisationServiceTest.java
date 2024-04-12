package uk.gov.di.authentication.oidc.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.HMRC200;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class InitiateIPVAuthorisationServiceTest {
    private static final String CLIENT_SESSION_ID = "client-session-v1";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-session-id";
    private static final String CLIENT_ID = "test-client-id";
    private static final List<LevelOfConfidence> LEVELS_OF_CONFIDENCE =
            List.of(HMRC200, MEDIUM_LEVEL);
    private static final String INTERNAL_SECTOR_URI = "https://ipv.account.gov.uk";
    private static final String SESSION_ID = "a-session-id";
    private static final String IPV_CLIENT_ID = "ipv-client-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");
    private static final String LANDING_PAGE_URL = "https//test.account.gov.uk/landingPage";
    private static final URI IPV_AUTHORISATION_URI = URI.create("http://localhost/ipv/authorize");
    private static final String ENVIRONMENT = "test-environment";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final String RP_PAIRWISE_ID = "urn:fdc:gov.uk:2022:dkjfshsdkjh";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final Boolean REPROVE_IDENTITY = true;
    private static final String SERIALIZED_JWT =
            "eyJraWQiOiIwOWRkYjY1ZWIzY2U0MWEzYjczYTJhOTM0ZTM5NDg4NmQyYTIyYjU0ZmQwMzVmYWJlZWM3YWMxYzllYzliNzBiIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOlsiaHR0cHM6Ly9jcmVkZW50aWFsLXN0b3JlLnRlc3QuYWNjb3VudC5nb3YudWsiLCJodHRwczovL2lkZW50aXR5LnRlc3QuYWNjb3VudC5nb3YudWsiXSwic3ViIjoia3NFUjVWcDRuZU1ONWM2WHJlSV9uUDhGNFZuc2VqS2x1b3BOX05mZjlfNCIsImlzcyI6Imh0dHBzOi8vb2lkYy50ZXN0LmFjY291bnQuZ292LnVrLyIsImV4cCI6MTcwOTA1MTE2MywiaWF0IjoxNzA5MDQ3NTYzLCJqdGkiOiJkZmNjZjc1MS1iZTU1LTRkZjQtYWEzZi1hOTkzMTkzZDUyMTYifQ.rpZ2IqMwlFLbZ8a7En-EuQ480zcorvNd-GZcwjlxlK3Twq9J1GNiuj9teSLINP_zmeirx7Y8p3DUYWk_hyRhww";

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final IPVAuthorisationService authorisationService =
            mock(IPVAuthorisationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private InitiateIPVAuthorisationService initiateAuthorisationService;
    private final TokenService tokenService = mock(TokenService.class);
    private APIGatewayProxyRequestEvent event;
    private final ClaimsSetRequest.Entry nameEntry =
            new ClaimsSetRequest.Entry("name").withClaimRequirement(ClaimRequirement.ESSENTIAL);
    private final ClaimsSetRequest.Entry birthDateEntry =
            new ClaimsSetRequest.Entry("birthdate")
                    .withClaimRequirement(ClaimRequirement.VOLUNTARY);
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest().add(nameEntry).add(birthDateEntry);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT_ID, "test.account.gov.uk", SaltHelper.generateNewSalt());
    private final AuthenticationRequest authenticationRequest = mock(AuthenticationRequest.class);
    private final UserInfo userInfo = generateUserInfo();
    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(EMAIL_ADDRESS)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);
    private final ClientRegistry client = generateClientRegistry();

    public InitiateIPVAuthorisationServiceTest() throws com.nimbusds.oauth2.sdk.ParseException {}

    @BeforeEach
    void setup() {
        initiateAuthorisationService =
                new InitiateIPVAuthorisationService(
                        configService,
                        auditService,
                        authorisationService,
                        cloudwatchMetricsService,
                        noSessionOrchestrationService,
                        tokenService);

        event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));

        when(configService.getIPVAuthorisationClientId()).thenReturn(IPV_CLIENT_ID);
        when(configService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configService.isIdentityEnabled()).thenReturn(true);
        when(configService.getIPVAuthorisationURI()).thenReturn(IPV_AUTHORISATION_URI);
        when(configService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(configService.sendStorageTokenToIpvEnabled()).thenReturn(true);
        when(configService.getStorageTokenClaimName())
                .thenReturn("https://vocab.account.gov.uk/v1/storageAccessToken");
        AccessToken storageToken = new BearerAccessToken(SERIALIZED_JWT, 180, null);
        when(tokenService.generateStorageToken(any())).thenReturn(storageToken);
    }

    @Test
    void shouldThrowWhenIdentityIsNotEnabled() {
        when(configService.isIdentityEnabled()).thenReturn(false);

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                initiateAuthorisationService.sendRequestToIPV(
                                        event,
                                        authenticationRequest,
                                        userInfo,
                                        session,
                                        client,
                                        CLIENT_ID,
                                        CLIENT_SESSION_ID,
                                        PERSISTENT_SESSION_ID,
                                        REPROVE_IDENTITY,
                                        LEVELS_OF_CONFIDENCE),
                        "Expected to throw exception");

        assertThat(exception.getMessage(), equalTo("Identity is not enabled"));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturn302AndRedirectURIWithClaims() throws JOSEException, ParseException {
        var encryptedJWT = createEncryptedJWT();
        when(authorisationService.constructRequestJWT(
                        any(State.class),
                        any(Scope.class),
                        any(Subject.class),
                        any(),
                        eq(CLIENT_SESSION_ID),
                        anyString(),
                        eq(List.of(HMRC200, MEDIUM_LEVEL)),
                        anyBoolean()))
                .thenReturn(encryptedJWT);

        var response =
                initiateAuthorisationService.sendRequestToIPV(
                        event,
                        createAuthenticationRequest(),
                        userInfo,
                        session,
                        client,
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REPROVE_IDENTITY,
                        LEVELS_OF_CONFIDENCE);

        assertThat(response, hasStatus(302));
        String redirectLocation = response.getHeaders().get("Location");
        assertThat(redirectLocation, startsWith(IPV_AUTHORISATION_URI.toString()));

        assertThat(splitQuery(redirectLocation).get("request"), equalTo(encryptedJWT.serialize()));
        verify(authorisationService).storeState(eq(session.getSessionId()), any(State.class));
        verify(noSessionOrchestrationService)
                .storeClientSessionIdAgainstState(eq(CLIENT_SESSION_ID), any(State.class));
        verify(tokenService).generateStorageToken(any());
        verify(authorisationService)
                .constructRequestJWT(
                        any(State.class),
                        eq(createAuthenticationRequest().getScope()),
                        any(Subject.class),
                        any(),
                        eq(CLIENT_SESSION_ID),
                        eq(EMAIL_ADDRESS),
                        eq(List.of(HMRC200, MEDIUM_LEVEL)),
                        eq(REPROVE_IDENTITY));
        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        CLIENT_ID,
                        expectedCommonSubject,
                        EMAIL_ADDRESS,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID,
                        pair("clientLandingPageUrl", LANDING_PAGE_URL),
                        pair("rpPairwiseId", RP_PAIRWISE_ID));
        verify(cloudwatchMetricsService)
                .incrementCounter("IPVHandoff", Map.of("Environment", ENVIRONMENT));
    }

    private EncryptedJWT createEncryptedJWT() throws JOSEException, ParseException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("key-id")
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("redirect_uri", "REDIRECT_URI")
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("client_id", "CLIENT_ID")
                        .claim("govuk_signin_journey_id", CLIENT_SESSION_ID)
                        .issuer("CLIENT_ID")
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        var rsaEncryptionKey =
                new RSAKeyGenerator(2048).keyID("encrytion-key-id").generate().toRSAPublicKey();
        var jweObject =
                new JWEObject(
                        new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                .contentType("JWT")
                                .build(),
                        new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(rsaEncryptionKey));
        return EncryptedJWT.parse(jweObject.serialize());
    }

    private UserInfo generateUserInfo() throws com.nimbusds.oauth2.sdk.ParseException {
        String jsonString =
                String.format(
                        """
                                {
                                    "sub": "urn:fdc:gov.uk:2022:jdgfhgfsdret",
                                    "legacy_subject_id": "odkjfshsdkjhdkjfshsdkjhdkjfshsdkjh",
                                    "public_subject_id": "pdkjfshsdkjhdkjfshsdkjhdkjfshsdkjh",
                                    "local_account_id": "dkjfshsdkjhdkjfshsdkjhdkjfshsdkjh",
                                    "rp_pairwise_id": "%s",
                                    "email": "%s",
                                    "email_verified": true,
                                    "phone_number": "007492837401",
                                    "phone_number_verified": true,
                                    "new_account": "true",
                                    "salt": ""
                                }
                                """,
                        RP_PAIRWISE_ID, EMAIL_ADDRESS);
        return UserInfo.parse(jsonString);
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withClientID(CLIENT_ID)
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withSectorIdentifierUri("http://sector-identifier")
                .withScopes(singletonList("openid"))
                .withCookieConsentShared(true)
                .withSubjectType("pairwise")
                .withLandingPageUrl(LANDING_PAGE_URL);
    }

    public static Map<String, String> splitQuery(String stringUrl) {
        URI uri = URI.create(stringUrl);
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String query = uri.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(
                    URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
        }
        return query_pairs;
    }

    private AuthenticationRequest createAuthenticationRequest() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(CLIENT_ID),
                        REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .claims(oidcClaimsRequest)
                .build();
    }
}
