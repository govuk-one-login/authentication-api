package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.CookieHelper;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private final SessionService sessionService;

    public LogoutHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
    }

    public LogoutHandler(ConfigurationService configurationService, SessionService sessionService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> sessionFromSessionCookie =
                sessionService.getSessionFromSessionCookie(input.getHeaders());
        return sessionFromSessionCookie
                .map(t -> processLogoutRequest(t, input))
                .orElse(generateDefaultLogoutResponse());
    }

    private APIGatewayProxyResponseEvent processLogoutRequest(
            Session session, APIGatewayProxyRequestEvent input) {
        Map<String, String> queryStringParameters = input.getQueryStringParameters();
        Optional<CookieHelper.SessionCookieIds> sessionCookieIds =
                CookieHelper.parseSessionCookie(input.getHeaders());

        boolean sessionContainsClientSessionID =
                session.getClientSessions()
                        .containsKey(sessionCookieIds.get().getClientSessionId());

        if (!sessionContainsClientSessionID) {
            throw new RuntimeException(
                    format(
                            "Client Session ID does not exist in Session: %s",
                            session.getSessionId()));
        }
        if (!queryStringParameters.containsKey("id_token_hint")
                || queryStringParameters.get("id_token_hint").isBlank()) {
            sessionService.deleteSessionFromRedis(session.getSessionId());
            return generateDefaultLogoutResponse();
        }
        if (!doesIDTokenExistInSession(queryStringParameters.get("id_token_hint"), session)) {
            throw new RuntimeException(
                    format("ID Token does not exist for Session: %s", session.getSessionId()));
        }
        if (!validateIDTokenSignature(
                queryStringParameters.get("id_token_hint"), session.getSessionId())) {
            throw new RuntimeException(
                    format(
                            "Unable to validate ID token signature for Session: %s",
                            session.getSessionId()));
        }

        sessionService.deleteSessionFromRedis(session.getSessionId());
        return generateDefaultLogoutResponse();
    }

    private boolean validateIDTokenSignature(String idTokenHint, String sessionID) {
        return true;
    }

    private boolean doesIDTokenExistInSession(String idTokenHint, Session session) {
        for (Map.Entry<String, ClientSession> t : session.getClientSessions().entrySet()) {
            boolean idTokenHintExists =
                    t.getValue().getIdTokenHint() != null
                            && t.getValue().getIdTokenHint().equals(idTokenHint);
            if (idTokenHintExists) {
                return true;
            }
        }
        return false;
    }

    private APIGatewayProxyResponseEvent generateDefaultLogoutResponse() {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of("Location", configurationService.getDefaultLogoutURI().toString()));
    }
}
