package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.Session;
import uk.gov.di.exceptions.ClientNotFoundException;
import uk.gov.di.helpers.CookieHelper;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.SessionService;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private final SessionService sessionService;
    private final DynamoClientService dynamoClientService;

    public LogoutHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    public LogoutHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
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

        if (!session.getClientSessions().containsKey(sessionCookieIds.get().getClientSessionId())) {
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
        if (!isIDTokenSignatureValid(
                queryStringParameters.get("id_token_hint"), session.getSessionId())) {
            throw new RuntimeException(
                    format(
                            "Unable to validate ID token signature for Session: %s",
                            session.getSessionId()));
        }
        try {
            String idTokenHint = queryStringParameters.get("id_token_hint");
            SignedJWT idToken = SignedJWT.parse(idTokenHint);
            Optional<String> audience =
                    idToken.getJWTClaimsSet().getAudience().stream().findFirst();
            return audience.map(
                            t -> {
                                final ClientRegistry clientRegistry;
                                try {
                                    clientRegistry =
                                            dynamoClientService
                                                    .getClient(t)
                                                    .orElseThrow(
                                                            () -> new ClientNotFoundException(t));
                                } catch (ClientNotFoundException e) {
                                    throw new RuntimeException(
                                            format(
                                                    "Client not found in ClientRegistry for ClientID: %s",
                                                    t));
                                }
                                String logoutURI =
                                        validateClientRedirectUri(
                                                queryStringParameters, clientRegistry);
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(Map.of("Location", logoutURI));
                            })
                    .orElse(generateDefaultLogoutResponse());
        } catch (ParseException e) {
            throw new RuntimeException();
        }
    }

    private boolean isIDTokenSignatureValid(String idTokenHint, String sessionID) {
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

    private String validateClientRedirectUri(
            Map<String, String> queryStringParameters, ClientRegistry clientRegistry) {
        String postLogoutRedirectUri = queryStringParameters.get("post_logout_redirect_uri");
        if (!queryStringParameters.get("post_logout_redirect_uri").isBlank()
                && clientRegistry.getPostLogoutRedirectUrls().contains(postLogoutRedirectUri)) {
            return postLogoutRedirectUri;
        }
        return configurationService.getDefaultLogoutURI().toString();
    }

    private APIGatewayProxyResponseEvent generateDefaultLogoutResponse() {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of("Location", configurationService.getDefaultLogoutURI().toString()));
    }
}
