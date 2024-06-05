package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.approvaltests.Approvals;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class WellknownHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);

    @Test
    void shouldReturn200WhenRequestIsSuccessful() {
        APIGatewayProxyResponseEvent result = getWellKnown();

        assertThat(result, hasStatus(200));
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
    void shouldReturnExpectedResponseBody() {
        APIGatewayProxyResponseEvent result = getWellKnown();

        Approvals.verify(result.getBody());
    }

    @Test
    void shouldThrowExceptionWhenBaseUrlIsMissing() {
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.empty());

        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> new WellknownHandler(configService),
                        "Expected to throw exception");

        assertThat(
                expectedException.getMessage(),
                equalTo("java.util.NoSuchElementException: No value present"));
    }

    private APIGatewayProxyResponseEvent getWellKnown() {
        when(configService.getOidcApiBaseURL()).thenReturn(Optional.of("http://localhost:8080"));
        when(configService.getFrontendBaseURL()).thenReturn("http://localhost:8081");

        WellknownHandler handler = new WellknownHandler(configService);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        return handler.handleRequest(event, context);
    }
}
