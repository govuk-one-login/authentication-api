package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.jwk.JWKSet;
import uk.gov.di.services.TokenService;

public class JwksHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private TokenService tokenService;

    public JwksHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    public JwksHandler() {
        this.tokenService = new TokenService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();

        JWKSet jwkSet;
        try {
            jwkSet = new JWKSet(tokenService.getSigningKey());
        } catch (IllegalArgumentException e) {
            apiGatewayProxyResponseEvent.setBody("Signing key is not present");
            apiGatewayProxyResponseEvent.setStatusCode(500);
            return apiGatewayProxyResponseEvent;
        }

        apiGatewayProxyResponseEvent.setBody(jwkSet.toString(true));
        apiGatewayProxyResponseEvent.setStatusCode(200);
        return apiGatewayProxyResponseEvent;
    }
}
