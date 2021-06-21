package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.entity.Session;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.InMemoryClientService;
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
    private final ConfigurationService configurationService;
    private final SessionService sessionService;

    private interface ResponseParameters {
        String SESSION_ID = "id";
        String SCOPE = "scope";
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
        this.clientService = new InMemoryClientService(new AuthorizationCodeService());
        this.configurationService = new ConfigurationService();
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
                                            authRequest.getScope().toString()));
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
            Map<String, List<String>> authRequest, LambdaLogger logger, String scope) {
        Session session = sessionService.createSession().setAuthenticationRequest(authRequest);
        logger.log("Created session " + session.getSessionId());
        sessionService.save(session);
        logger.log("Session saved successfully " + session.getSessionId());
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of(
                                "Location",
                                format(
                                        "%s?%s&%s",
                                        configurationService.getLoginURI(),
                                        buildEncodedParam(
                                                ResponseParameters.SESSION_ID,
                                                session.getSessionId()),
                                        buildEncodedParam(ResponseParameters.SCOPE, scope))));
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
}
