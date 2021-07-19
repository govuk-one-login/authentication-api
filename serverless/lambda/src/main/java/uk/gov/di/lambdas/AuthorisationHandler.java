package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.entity.Session;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.SessionService;

import java.net.URLEncoder;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final SessionService sessionService;
    private final ConfigurationService configurationService;

    private interface ResponseParameters {
        String SESSION_ID = "id";
        String SCOPE = "scope";
    }

    private interface ResponseHeaders {
        String LOCATION = "Location";
        String SET_COOKIE = "Set-Cookie";
    }

    public AuthorisationHandler(
            ClientService clientService,
            ConfigurationService configurationService,
            SessionService sessionService) {
        this.clientService = clientService;
        this.configurationService = configurationService;
        this.sessionService = sessionService;
    }

    public AuthorisationHandler() {
        configurationService = new ConfigurationService();
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.sessionService = new SessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();
        logger.log("Received authentication request");
        try {
            Map<String, List<String>> queryStringMultiValuedMap =
                    input.getQueryStringParameters().entrySet().stream()
                            .collect(
                                    Collectors.toMap(
                                            entry -> entry.getKey(),
                                            entry -> List.of(entry.getValue())));
            var authRequest = AuthenticationRequest.parse(queryStringMultiValuedMap);

            Optional<ErrorObject> error =
                    clientService.getErrorForAuthorizationRequest(authRequest);

            return error.map(e -> errorResponse(authRequest, e))
                    .orElseGet(
                            () ->
                                    createSessionAndRedirect(
                                            queryStringMultiValuedMap,
                                            logger,
                                            authRequest.getScope(),
                                            authRequest.getClientID()));
        } catch (ParseException e) {
            logger.log("Authentication request could not be parsed");
            logger.log(e.getMessage());
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            response.setStatusCode(400);
            response.setBody("Cannot parse authentication request");

            return response;
        }
    }

    private APIGatewayProxyResponseEvent createSessionAndRedirect(
            Map<String, List<String>> authRequest,
            LambdaLogger logger,
            Scope scope,
            ClientID clientId) {
        Session session = sessionService.createSession();
        session.addClientSessionAuthorisationRequest(session.getClientSessionId(), authRequest);
        logger.log(
                format(
                        "Created session %s for client %s - client session id = %s",
                        session.getSessionId(), clientId.getValue(), session.getClientSessionId()));
        sessionService.save(session);
        logger.log("Session saved successfully " + session.getSessionId());
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of(
                                ResponseHeaders.LOCATION,
                                buildLocationString(scope, session),
                                ResponseHeaders.SET_COOKIE,
                                buildCookieString(session)));
    }

    private APIGatewayProxyResponseEvent errorResponse(
            AuthorizationRequest authRequest, ErrorObject errorObject) {
        AuthenticationErrorResponse error =
                new AuthenticationErrorResponse(
                        authRequest.getRedirectionURI(),
                        errorObject,
                        authRequest.getState(),
                        authRequest.getResponseMode());

        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of("Location", error.toURI().toString()));
    }

    private String buildEncodedParam(String name, String value) {
        return format("%s=%s", name, URLEncoder.encode(value));
    }

    private String buildLocationString(Scope scope, Session session) {
        return format(
                "%s?%s&%s",
                configurationService.getLoginURI(),
                buildEncodedParam(
                        ResponseParameters.SESSION_ID,
                        session.getSessionId()),
                buildEncodedParam(
                        ResponseParameters.SCOPE, scope.toString()));
    }

    private String buildCookieString(Session session) {
        return format(
                "%s=%s.%s",
                "gs",
                session.getSessionId(),
                session.getClientSessionId());
    }
}
