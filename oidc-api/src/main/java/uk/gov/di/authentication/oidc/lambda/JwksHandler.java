package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class JwksHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final TokenValidationService tokenValidationService;
    private final ConfigurationService configurationService;
    private static final Logger LOG = LoggerFactory.getLogger(JwksHandler.class);

    public JwksHandler(
            TokenValidationService tokenValidationService,
            ConfigurationService configurationService) {
        this.tokenValidationService = tokenValidationService;
        this.configurationService = configurationService;
    }

    public JwksHandler() {
        this.configurationService = new ConfigurationService();
        this.tokenValidationService =
                new TokenValidationService(
                        configurationService, new KmsConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            JWKSet jwkSet;
                            try {
                                LOG.info("JWKs request received");
                                jwkSet = new JWKSet(tokenValidationService.getPublicJwk());
                            } catch (IllegalArgumentException e) {
                                LOG.error("Error in JWKs lambda. Public Jwk is null", e);
                                return generateApiGatewayProxyResponse(
                                        500, "Signing key is not present");
                            }
                            LOG.info("Generating JWKs successful response");
                            return generateApiGatewayProxyResponse(200, jwkSet.toString(true));
                        });
    }
}
