package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.jwk.JWKSet;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.TokenService;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class JwksHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final TokenService tokenService;
    private final ConfigurationService configurationService;

    public JwksHandler(TokenService tokenService, ConfigurationService configurationService) {
        this.tokenService = tokenService;
        this.configurationService = configurationService;
    }

    public JwksHandler() {
        this.configurationService = new ConfigurationService();
        this.tokenService =
                new TokenService(
                        configurationService, new RedisConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        JWKSet jwkSet;
        try {
            jwkSet = new JWKSet(tokenService.getSigningKey());
        } catch (IllegalArgumentException e) {
            return generateApiGatewayProxyResponse(500, "Signing key is not present");
        }
        return generateApiGatewayProxyResponse(200, jwkSet.toString(true));
    }
}
