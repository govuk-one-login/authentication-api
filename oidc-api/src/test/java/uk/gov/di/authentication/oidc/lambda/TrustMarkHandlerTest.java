package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.TrustMarkResponse;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class TrustMarkHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context context = mock(Context.class);
    private static final String BASE_URL = "https://example.com";
    private TrustMarkHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new TrustMarkHandler(configurationService);
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getOidcApiBaseURL()).thenReturn(baseUrl);
    }

    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws JsonProcessingException {
        TrustMarkResponse trustMarkResponse =
                new TrustMarkResponse(
                        configurationService.getOidcApiBaseURL().orElseThrow(),
                        configurationService.getOidcApiBaseURL().orElseThrow(),
                        List.of(
                                CredentialTrustLevel.LOW_LEVEL.getValue(),
                                CredentialTrustLevel.MEDIUM_LEVEL.getValue()),
                        LevelOfConfidence.getAllSupportedLevelOfConfidenceValues());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        TrustMarkResponse response =
                ObjectMapperFactory.getInstance()
                        .readValue(result.getBody(), TrustMarkResponse.class);

        assertEquals(response.getIdp(), trustMarkResponse.getIdp());
        assertEquals(response.getTrustMark(), trustMarkResponse.getTrustMark());
        assertEquals(response.getC(), trustMarkResponse.getC());
        assertEquals(response.getP(), trustMarkResponse.getP());
    }
}
