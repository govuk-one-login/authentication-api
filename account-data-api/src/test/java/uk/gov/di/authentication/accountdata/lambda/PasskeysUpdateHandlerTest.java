package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class PasskeysUpdateHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasskeysUpdateHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysUpdateHandler(configurationService);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn204ForValidRequest() {
            var result = handler.handleRequest(passkeysUpdateRequest(), context);
            assertThat(result, hasStatus(204));
        }
    }

    @Nested
    class Error {
        @Test
        void shouldReturn400WhenReadValueFails() throws Json.JsonException {
            var objectMapperMock = mock(SerializationService.class);
            handler = new PasskeysUpdateHandler(configurationService, objectMapperMock);
            when(objectMapperMock.readValue(any(), any(), anyBoolean()))
                    .thenThrow(new Json.JsonException("json-exception"));

            var result = handler.handleRequest(passkeysUpdateRequest(), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.UNEXPECTED_ACCOUNT_DATA_API_ERROR));
        }
    }

    private APIGatewayProxyRequestEvent passkeysUpdateRequest() {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withBody("{}")
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }
}
