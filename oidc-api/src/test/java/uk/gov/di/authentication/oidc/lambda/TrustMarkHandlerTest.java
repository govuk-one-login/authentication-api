package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.TrustMarkResponse;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class TrustMarkHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context context = mock(Context.class);
    private static final URI BASE_URL = URI.create("https://example.com");
    private TrustMarkHandler handler;
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    public void setUp() {
        handler = new TrustMarkHandler(configurationService);
        var baseUrl = Optional.of(BASE_URL);
        when(configurationService.getOidcApiBaseURL()).thenReturn(baseUrl);
    }

    @Test
    void shouldReturn200WhenRequestIsSuccessful() throws Json.JsonException {
        TrustMarkResponse trustMarkResponse =
                new TrustMarkResponse(
                        configurationService.getOidcApiBaseURL().map(URI::toString).orElseThrow(),
                        configurationService.getOidcApiBaseURL().map(URI::toString).orElseThrow(),
                        List.of(
                                CredentialTrustLevel.LOW_LEVEL.getValue(),
                                CredentialTrustLevel.MEDIUM_LEVEL.getValue()),
                        LevelOfConfidence.getAllSupportedLevelOfConfidenceValues());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        TrustMarkResponse response =
                objectMapper.readValue(result.getBody(), TrustMarkResponse.class);

        assertEquals(response.getIdp(), trustMarkResponse.getIdp());
        assertEquals(response.getTrustMark(), trustMarkResponse.getTrustMark());
        assertEquals(response.getC(), trustMarkResponse.getC());
        assertEquals(response.getP(), trustMarkResponse.getP());
    }
}
