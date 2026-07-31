package uk.gov.di.orchestration.identity.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityContextServiceTest {
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final State STATE = new State();

    private IdentityContextService service;

    @BeforeEach
    void setup() {
        service = new IdentityContextService(crossBrowserOrchestrationService);
    }

    @Test
    void
            shouldThrowCrossBrowserNoSessionExceptionWhenNoSessionCookiesAreSetAndSessionFoundUsingState()
                    throws Exception {
        var request = createRequestEvent();
        request.setHeaders(Map.of(COOKIE, ""));
        mockCrossBrowserReturningNoSessionEntity(request);

        assertThrows(CrossBrowserNoSessionException.class, () -> service.buildContext(request));
    }

    @Test
    void shouldThrowNoSessionExceptionWhenNoSessionCookiesAreSetAndSessionNotFoundUsingState()
            throws Exception {
        var request = createRequestEvent();
        request.setHeaders(Map.of(COOKIE, ""));
        mockNoSessionFoundFromState(request);

        assertThrows(NoSessionException.class, () -> service.buildContext(request));
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

    private void mockCrossBrowserReturningNoSessionEntity(APIGatewayProxyRequestEvent request)
            throws Exception {
        var noSessionCrossBrowserEntity =
                new CrossBrowserEntity(
                        "test-csid",
                        new ErrorObject("test-error", "Test Description"),
                        new OrchClientSessionItem("test-csid"));
        when(crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
                        request.getQueryStringParameters()))
                .thenReturn(noSessionCrossBrowserEntity);
    }

    private void mockNoSessionFoundFromState(APIGatewayProxyRequestEvent request) throws Exception {
        when(crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
                        request.getQueryStringParameters()))
                .thenThrow(new NoSessionException("test"));
    }
}
