package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class WellknownHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private WellknownHandler handler;


    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws ParseException {
        when(configService.getBaseURL()).thenReturn(Optional.of("http://localhost:8080"));
        handler = new WellknownHandler(configService);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        URI expectedRegistrationURI = URI.create("http://localhost:8080/connect/register");

        assertThat(result, hasStatus(200));
        assertEquals(
                List.of(GrantType.AUTHORIZATION_CODE),
                OIDCProviderMetadata.parse(result.getBody()).getGrantTypes());
        assertEquals(
                List.of(ClaimType.NORMAL),
                OIDCProviderMetadata.parse(result.getBody()).getClaimTypes());
        assertEquals(
                expectedRegistrationURI,
                OIDCProviderMetadata.parse(result.getBody()).getRegistrationEndpointURI());
    }

    @Test
    public void shouldThrowExceptionWhenBaseUrlIsMissing() {
        when(configService.getBaseURL()).thenReturn(Optional.empty());

                assertThrows(
                        NoSuchElementException.class,
                        () -> new WellknownHandler(configService),
                        "Expected to throw exception");
    }
}
