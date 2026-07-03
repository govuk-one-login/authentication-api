package uk.gov.di.orchestration.sis.service;

import com.google.gson.GsonBuilder;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
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
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.orchestration.sharedtest.utils.JwtUtils.createDummyJwt;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

class SISAuthorisationServiceTest {
    private static final String KEY_ID = "14342354354353";
    private static final String SIS_CLIENT_ID = "sis-client-id";
    private static final URI SIS_URI = URI.create("http://sis/");
    private static final URI SIS_AUTHORISATION_URI = URI.create("http://sis/oauth2/authorize");
    private static final URI SIS_CALLBACK_URI = URI.create("http://localhost/oidc/sis/callback");
    private static final String SIS_SIGNING_KEY_ALIAS = "test-signing-key-id";
    private static final Instant NOW = Instant.parse("2026-06-29T15:00:00Z");
    private static final String CLIENT_SESSION_ID = "client-session-v1";
    private static final String CLIENT_ID = "test-client-id";
    private static final List<String> LEVELS_OF_CONFIDENCE = List.of("P0", "P2");
    private static final String SESSION_ID = "a-session-id";
    private static final String RP_PAIRWISE_ID = "urn:fdc:gov.uk:2022:dkjfshsdkjh";
    private final ClaimsSetRequest.Entry nameEntry =
            new ClaimsSetRequest.Entry("name").withClaimRequirement(ClaimRequirement.ESSENTIAL);
    private final ClaimsSetRequest.Entry birthDateEntry =
            new ClaimsSetRequest.Entry("birthdate")
                    .withClaimRequirement(ClaimRequirement.VOLUNTARY);
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest().add(nameEntry).add(birthDateEntry);
    private final AccessToken storageToken = new BearerAccessToken("test-token", 180, null);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private final JwksCacheService jwksCacheService = mock(JwksCacheService.class);
    private final OrchJwtService orchJwtService = mock(OrchJwtService.class);
    private SISAuthorisationService authorisationService;

    private RSAPublicKey publicEncKey;

    @BeforeEach
    void setup() throws Exception {
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        when(configurationService.getSISAuthorisationClientId()).thenReturn(SIS_CLIENT_ID);
        when(configurationService.getSISAuthorisationCallbackURI()).thenReturn(SIS_CALLBACK_URI);
        when(configurationService.getSISAudience()).thenReturn(SIS_URI.toString());
        var keyPair = generateRsaKeyPair();
        var publicEncJwk =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyUse(KeyUse.ENCRYPTION)
                        .keyID(KEY_ID)
                        .build();
        publicEncKey = publicEncJwk.toRSAPublicKey();
        var jwksUrl = new URL("http://localhost/.well-known/jwks.json");
        when(configurationService.getSISJwksUrl()).thenReturn(jwksUrl);
        when(jwksCacheService.getOrGenerateSISJwksCacheItem())
                .thenReturn(new JwksCacheItem(jwksUrl.toString(), publicEncJwk, 300));
        when(configurationService.getSISTokenSigningKeyAlias()).thenReturn(SIS_SIGNING_KEY_ALIAS);
        when(configurationService.getStorageTokenClaimName())
                .thenReturn("https://vocab.account.gov.uk/v1/storageAccessToken");
        when(configurationService.getSISAuthorisationURI()).thenReturn(SIS_AUTHORISATION_URI);

        when(tokenService.generateStorageToken(any(), eq(SIS_URI.toString())))
                .thenReturn(storageToken);

        authorisationService =
                new SISAuthorisationService(
                        configurationService,
                        tokenService,
                        stateStorageService,
                        crossBrowserOrchestrationService,
                        jwksCacheService,
                        orchJwtService,
                        new NowHelper.NowClock(Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    @Test
    void shouldThrowWhenIdentityIsNotEnabled() throws ParseException {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        var authRequest = createAuthenticationRequest(claimsSetRequest);
        var userInfo = generateUserInfo();

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                authorisationService.sendRequest(
                                        authRequest,
                                        userInfo,
                                        CLIENT_ID,
                                        SESSION_ID,
                                        CLIENT_SESSION_ID,
                                        false,
                                        LEVELS_OF_CONFIDENCE),
                        "Expected to throw exception");

        assertThat(exception.getMessage(), equalTo("Identity is not enabled"));
    }

    @Test
    void shouldCreateASignedAndEncryptedJwt() {
        var state = new State("test-state");
        var scope = new Scope(OIDCScopeValue.OPENID);
        var pairwise = new Subject("pairwise-identifier");
        var claims =
                new ClaimsSetRequest()
                        .add(
                                new ClaimsSetRequest.Entry(
                                                "https://vocab.account.gov.uk/v1/coreIdentityJWT")
                                        .withClaimRequirement(ClaimRequirement.ESSENTIAL));
        var clientSessionId = "test-csid";
        var email = "test@email.com";
        var vtrList = List.of("P2");
        var jwtId = "test-jwt-id";
        try (MockedStatic<IdGenerator> mockedIdGenerator = mockStatic(IdGenerator.class)) {
            mockedIdGenerator.when(IdGenerator::generate).thenReturn(jwtId);
            authorisationService.constructRequestJWT(
                    state, scope, pairwise, claims, clientSessionId, email, vtrList, null);
        }
        var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);

        verify(orchJwtService)
                .signAndEncryptJWT(captor.capture(), eq(SIS_SIGNING_KEY_ALIAS), eq(publicEncKey));
        var actualClaims = captor.getValue();
        assertThat(actualClaims.getJWTID(), equalTo(jwtId));
        assertThat(actualClaims.getClaim("client_id"), equalTo(SIS_CLIENT_ID));
        assertThat(actualClaims.getClaim("state"), equalTo(state.getValue()));
        assertThat(actualClaims.getSubject(), equalTo(pairwise.getValue()));
        assertThat(actualClaims.getClaim("scope"), equalTo(scope.toString()));
        assertThat(actualClaims.getIssuer(), equalTo(SIS_CLIENT_ID));
        assertThat(actualClaims.getAudience(), equalTo(singletonList(SIS_URI.toString())));
        assertThat(actualClaims.getClaim("response_type"), equalTo("code"));
        var expectedClaimsRequest =
                new OIDCClaimsRequest().withUserInfoClaimsRequest(claims).toJSONObject();
        assertThat(actualClaims.getClaim("claims"), equalTo(expectedClaimsRequest));
        assertThat(actualClaims.getClaim("email_address"), equalTo(email));
        assertThat(actualClaims.getClaim("govuk_signin_journey_id"), equalTo(clientSessionId));
        assertThat(actualClaims.getClaim("vtr"), equalTo(vtrList));
        assertNull(actualClaims.getClaim("reprove_identity"));
        assertThat(actualClaims.getClaim("redirect_uri"), equalTo(SIS_CALLBACK_URI.toString()));
        assertThat(actualClaims.getIssueTime(), equalTo(Date.from(NOW)));
        assertThat(actualClaims.getNotBeforeTime(), equalTo(Date.from(NOW)));
        assertThat(
                actualClaims.getExpirationTime(),
                equalTo(Date.from(NOW.plus(3, ChronoUnit.MINUTES))));

        JsonApprovals.verifyAsJson(actualClaims.toJSONObject(), GsonBuilder::serializeNulls);
    }

    @Test
    void shouldReturn302AndRedirectURIWithClaims() throws Exception {
        var dummyJwt = createDummyJwt();
        when(orchJwtService.signAndEncryptJWT(any(), anyString(), any())).thenReturn(dummyJwt);
        var authRequest = createAuthenticationRequest(claimsSetRequest);
        var userInfo = generateUserInfo();
        var response =
                authorisationService.sendRequest(
                        authRequest,
                        userInfo,
                        CLIENT_ID,
                        SESSION_ID,
                        CLIENT_SESSION_ID,
                        false,
                        LEVELS_OF_CONFIDENCE);
        assertThat(response, hasStatus(302));
        String redirectLocation = response.getHeaders().get("Location");
        assertThat(redirectLocation, startsWith(SIS_AUTHORISATION_URI.toString()));

        assertThat(splitQuery(redirectLocation).get("request"), equalTo(dummyJwt.serialize()));
        verify(stateStorageService).storeState(eq("sis-state:" + SESSION_ID), anyString());
        verify(crossBrowserOrchestrationService)
                .storeClientSessionIdAgainstState(eq(CLIENT_SESSION_ID), any(State.class));
    }

    private static Map<String, String> splitQuery(String stringUrl) {
        URI uri = URI.create(stringUrl);
        Map<String, String> queryPairs = new LinkedHashMap<>();
        String query = uri.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            queryPairs.put(
                    URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
        }
        return queryPairs;
    }

    private AuthenticationRequest createAuthenticationRequest(
            ClaimsSetRequest authenticationClaimSetRequest) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var oidcClaimsRequest =
                new OIDCClaimsRequest().withUserInfoClaimsRequest(authenticationClaimSetRequest);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(CLIENT_ID),
                        SIS_AUTHORISATION_URI)
                .state(new State())
                .nonce(new Nonce())
                .claims(oidcClaimsRequest)
                .build();
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
                                    "email": "test@email.com",
                                    "email_verified": true,
                                    "phone_number": "007492837401",
                                    "phone_number_verified": true,
                                    "new_account": "true",
                                    "salt": ""
                                }
                                """,
                        RP_PAIRWISE_ID);
        return UserInfo.parse(jsonString);
    }
}
