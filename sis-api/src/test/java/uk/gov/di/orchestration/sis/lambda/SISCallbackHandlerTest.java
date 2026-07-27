package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.identity.helpers.IdentityCallbackHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class SISCallbackHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final IdentityCallbackHelper identityCallbackHelper =
            mock(IdentityCallbackHelper.class);
    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final State STATE = new State();
    private SISCallbackHandler handler;

    @BeforeEach
    void setup() {
        when(identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(any(Throwable.class)))
                .thenReturn(
                        RedirectService.redirectToFrontendErrorPageWithErrorLog(
                                FRONT_END_ERROR_URI, new Error("error")));
        handler = new SISCallbackHandler(configurationService, identityCallbackHelper);
    }

    @Test
    void shouldRedirectToErrorPageWhenIdentityIsDisabled() {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        var request = createRequestEvent();

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToPage(response, FRONT_END_ERROR_URI.toString());
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s di-persistent-session-id=%s; Max-Age=34190000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                "gs",
                SESSION_ID,
                CLIENT_SESSION_ID,
                3600,
                "Secure; HttpOnly;",
                PERSISTENT_SESSION_ID);
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        return createRequestEvent(Map.of());
    }

    private APIGatewayProxyRequestEvent createRequestEvent(Map<String, String> extraParams) {
        Map<String, String> responseParams = new HashMap<>();
        responseParams.put("code", AUTH_CODE.getValue());
        responseParams.put("state", STATE.getValue());
        responseParams.putAll(extraParams);
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseParams);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
    }

    private void assertDoesRedirectToPage(APIGatewayProxyResponseEvent response, String page) {
        assertThat(response, hasStatus(302));
        assertEquals(page, response.getHeaders().get("Location"));
    }
}
