package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AMCCallbackRequest;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;

class AMCCallbackHandlerTest {
    private static final Context CONTEXT = mock(Context.class);
    private static final UserContext USER_CONTEXT = mock(UserContext.class);

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final AuthSessionService authSessionService = mock(AuthSessionService.class);

    private static final String STATE = "state";
    private static final String AUTH_CODE = "1234";

    @BeforeAll
    static void setUp() {
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
    }

    @Test
    void shouldReturn200ForBasicHandler() {
        AMCCallbackHandler handler =
                new AMCCallbackHandler(
                        configurationService, authenticationService, authSessionService);

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertEquals("very cool", result.getBody());
    }
}
