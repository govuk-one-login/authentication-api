package uk.gov.di.authentication.local.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class ApiGatewayLambdaHandler {
    private static final Logger LOG = LogManager.getLogger(ApiGatewayLambdaHandler.class);
    private static final LocalLambdaContext LAMBDA_CONTEXT = new LocalLambdaContext();

    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
            lambdaHandler;

    public static Handler handlerFor(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
                    lambdaHandler) {
        return new ApiGatewayLambdaHandler(lambdaHandler)::handle;
    }

    public ApiGatewayLambdaHandler(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
                    lambdaHandler) {
        this.lambdaHandler = lambdaHandler;
    }

    public void handle(Context ctx) {
        try {
            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                    new APIGatewayProxyRequestEvent();
            apiGatewayProxyRequestEvent.setHttpMethod(ctx.method().name());
            apiGatewayProxyRequestEvent.setBody(ctx.body());
            apiGatewayProxyRequestEvent.setHeaders(ctx.headerMap());
            apiGatewayProxyRequestEvent.setPath(ctx.path());
            apiGatewayProxyRequestEvent.setPathParameters(ctx.pathParamMap());
            // N.B. this will only take the first query param value
            apiGatewayProxyRequestEvent.setQueryStringParameters(
                    ctx.queryParamMap().entrySet().stream()
                            .collect(
                                    Collectors.toMap(
                                            Map.Entry::getKey, (e) -> e.getValue().get(0))));

            var authorizationHeader = ctx.headerMap().get("Authorization");
            if (authorizationHeader != null) {
                attachRequestContextToEvent(apiGatewayProxyRequestEvent, authorizationHeader);
            }

            APIGatewayProxyResponseEvent responseEvent =
                    lambdaHandler.handleRequest(apiGatewayProxyRequestEvent, LAMBDA_CONTEXT);

            ctx.status(responseEvent.getStatusCode()).json(responseEvent.getBody());
            responseEvent.getHeaders().forEach(ctx::header);
        } catch (RuntimeException | ParseException | com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Runtime exception thrown by handler", e);
            ctx.status(500).json(Map.of("message", e.getMessage()));
        }
    }

    private void attachRequestContextToEvent(
            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent, String authorizationHeader)
            throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
        var accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        var signedAccessToken = SignedJWT.parse(accessToken.getValue());
        var claimsSet = signedAccessToken.getJWTClaimsSet();

        var authorizer = new HashMap<String, Object>();
        authorizer.put("principalId", claimsSet.getSubject());
        authorizer.put("scope", claimsSet.getClaim("scope"));

        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();
        requestContext.setAuthorizer(authorizer);
        apiGatewayProxyRequestEvent.setRequestContext(requestContext);
    }
}
