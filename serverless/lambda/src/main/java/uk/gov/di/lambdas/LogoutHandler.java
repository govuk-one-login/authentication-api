package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.entity.Session;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.util.Map;
import java.util.Optional;

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

        if (!queryStringParameters.containsKey("id_token_hint")
                || queryStringParameters.get("id_token_hint").isBlank()) {
            sessionService.deleteSessionFromRedis(session.getSessionId());
            return generateDefaultLogoutResponse();
        }
        sessionService.deleteSessionFromRedis(session.getSessionId());
        return generateDefaultLogoutResponse();
    }

    private APIGatewayProxyResponseEvent generateDefaultLogoutResponse() {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of("Location", configurationService.getDefaultLogoutURI().toString()));
    }
}
