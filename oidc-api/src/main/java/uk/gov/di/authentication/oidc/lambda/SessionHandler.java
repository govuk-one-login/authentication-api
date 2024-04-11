package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackException;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class SessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CookieHelper cookieHelper = new CookieHelper();
    private final SessionService sessionService;

    public SessionHandler() {
        var configurationService = ConfigurationService.getInstance();
        this.sessionService = new SessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        CookieHelper.SessionCookieIds sessionCookiesIds =
                cookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);

        if (sessionCookiesIds == null) {
            throw new AuthenticationCallbackException("No session cookie found");
        }

        Session userSession =
                sessionService
                        .readSessionFromRedis(sessionCookiesIds.getSessionId())
                        .orElseThrow(
                                () ->
                                        new AuthenticationCallbackException(
                                                "Orchestration user session not found"));

        return generateApiGatewayProxyResponse(
                200, SerializationService.getInstance().writeValueAsString(userSession));
    }
}
