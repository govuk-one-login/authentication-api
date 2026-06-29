package uk.gov.di.orchestration.sis.service;

import com.google.gson.GsonBuilder;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;

import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

class SISAuthorisationServiceTest {
    private static final String KEY_ID = "14342354354353";
    private static final String SIS_CLIENT_ID = "sis-client-id";
    private static final URI SIS_URI = URI.create("http://sis/");
    private static final URI SIS_CALLBACK_URI = URI.create("http://localhost/oidc/sis/callback");
    private static final String SIS_SIGNING_KEY_ALIAS = "test-signing-key-id";
    private static final Instant NOW = Instant.parse("2026-06-29T15:00:00Z");

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final JwksCacheService jwksCacheService = mock(JwksCacheService.class);
    private final OrchJwtService orchJwtService = mock(OrchJwtService.class);
    private SISAuthorisationService authorisationService;

    private RSAPublicKey publicEncKey;

    @BeforeEach
    void setup() throws Exception {
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

        authorisationService =
                new SISAuthorisationService(
                        configurationService,
                        jwksCacheService,
                        orchJwtService,
                        new NowHelper.NowClock(Clock.fixed(NOW, ZoneOffset.UTC)));
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
}
