package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.TrustMarkResponse;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class TrustMarkHandlerTest {

    private final OidcAPI oidcApi = mock(OidcAPI.class);
    private final Context context = mock(Context.class);
    private static final URI OIDC_BASE_URI = URI.create("https://example.com");
    private TrustMarkHandler handler;
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    public void setUp() {
        when(oidcApi.baseURI()).thenReturn(OIDC_BASE_URI);
        handler = new TrustMarkHandler(oidcApi);
    }

    @Test
    void shouldReturn200WhenRequestIsSuccessful() throws Json.JsonException {
        TrustMarkResponse expectedTrustMarkResponse =
                new TrustMarkResponse(
                        OIDC_BASE_URI.toString(),
                        OIDC_BASE_URI.toString(),
                        List.of(
                                CredentialTrustLevel.LOW_LEVEL.getValue(),
                                CredentialTrustLevel.MEDIUM_LEVEL.getValue()),
                        List.of(
                                LevelOfConfidence.NONE.getValue(),
                                LevelOfConfidence.LOW_LEVEL.getValue(),
                                LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                                LevelOfConfidence.HIGH_LEVEL.getValue()));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        TrustMarkResponse actualTrustMarkResponse =
                objectMapper.readValue(result.getBody(), TrustMarkResponse.class);

        assertEquals(actualTrustMarkResponse.getIdp(), expectedTrustMarkResponse.getIdp());
        assertEquals(
                actualTrustMarkResponse.getTrustMark(), expectedTrustMarkResponse.getTrustMark());
        assertEquals(actualTrustMarkResponse.getC(), expectedTrustMarkResponse.getC());
        assertEquals(actualTrustMarkResponse.getP(), expectedTrustMarkResponse.getP());
    }
}
