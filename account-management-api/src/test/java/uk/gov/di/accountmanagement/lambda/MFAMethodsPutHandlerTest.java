package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;

class MFAMethodsPutHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final Context context = mock(Context.class);

    private MFAMethodsPutHandler handler;

    private final APIGatewayProxyRequestEvent event =
            new APIGatewayProxyRequestEvent()
                    .withPathParameters(
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", "some-subject-id"),
                                    Map.entry("mfaIdentifier", "some-mfa-identifier")))
                    .withHeaders(VALID_HEADERS);

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler = new MFAMethodsPutHandler(configurationService);
    }

    @Test
    void shouldReturn204WhenFeatureFlagEnabled() {
        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
    }

    @Test
    void shouldReturn400WhenFeatureFlagDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());
    }
}
