package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class WellknownHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private final OidcAPI oidcApi = mock(OidcAPI.class);

    @Test
    void shouldReturn200WhenRequestIsSuccessful() {
        APIGatewayProxyResponseEvent result = getWellKnown();

        assertThat(result, hasStatus(200));
    }

    @Test
    void shouldReturnCacheControlHeader() {
        APIGatewayProxyResponseEvent result = getWellKnown();

        assertThat(result.getHeaders().get("Cache-Control"), equalTo("max-age=86400"));
    }

    @Test
    void shouldContainAllOneLoginClaims() throws ParseException {
        APIGatewayProxyResponseEvent result = getWellKnown();
        var metadata = OIDCProviderMetadata.parse(result.getBody());

        ValidClaims.allOneLoginClaims()
                .forEach(claim -> assertTrue(metadata.getClaims().contains(claim)));
    }

    @Test
    void shouldContainCorrectGrantAndClaimTypes() throws ParseException {
        APIGatewayProxyResponseEvent result = getWellKnown();
        var metadata = OIDCProviderMetadata.parse(result.getBody());

        assertThat(metadata.getGrantTypes(), equalTo(List.of(GrantType.AUTHORIZATION_CODE)));
        assertThat(metadata.getClaimTypes(), equalTo(List.of(ClaimType.NORMAL)));
    }

    @Test
    void shouldContainCorrectCodeChallengeMethods() throws ParseException {
        APIGatewayProxyResponseEvent result = getWellKnown();
        var metadata = OIDCProviderMetadata.parse(result.getBody());

        assertThat(metadata.getCodeChallengeMethods(), equalTo(List.of(CodeChallengeMethod.S256)));
    }

    @Test
    void shouldReturnExpectedResponseBody() throws ParseException {
        APIGatewayProxyResponseEvent result = getWellKnown();
        var bodyAsJson = OIDCProviderMetadata.parse(result.getBody()).toJSONObject();
        JsonApprovals.verifyAsJson(bodyAsJson);
    }

    private APIGatewayProxyResponseEvent getWellKnown() {
        when(oidcApi.baseURI()).thenReturn(URI.create("http://localhost:8080"));
        when(oidcApi.tokenURI()).thenReturn(URI.create("http://localhost:8080/token"));
        when(oidcApi.trustmarkURI()).thenReturn(URI.create("http://localhost:8080/trustmark"));
        when(oidcApi.authorizeURI()).thenReturn(URI.create("http://localhost:8080/authorize"));
        when(oidcApi.logoutURI()).thenReturn(URI.create("http://localhost:8080/logout"));
        when(oidcApi.userInfoURI()).thenReturn(URI.create("http://localhost:8080/userinfo"));
        when(oidcApi.registerationURI())
                .thenReturn(URI.create("http://localhost:8080/connect/register"));
        when(oidcApi.wellKnownURI())
                .thenReturn(URI.create("http://localhost:8080/.well-known/jwks.json"));

        when(authFrontend.privacyNoticeURI())
                .thenReturn(URI.create("http://localhost:8081/privacy-notice"));
        when(authFrontend.termsOfServiceURI())
                .thenReturn(URI.create("http://localhost:8081/terms-and-conditions"));

        WellknownHandler handler = new WellknownHandler(authFrontend, oidcApi, configService);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        return handler.handleRequest(event, context);
    }
}
