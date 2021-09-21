package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import uk.gov.di.authentication.oidc.entity.TrustMarkResponse;
import uk.gov.di.authentication.shared.entity.AuthenticationValues;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class TrustMarkHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;

    public TrustMarkHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public TrustMarkHandler() {
        this.configurationService = new ConfigurationService();
    }

    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            try {
                                return generateApiGatewayProxyResponse(
                                        200, createTrustMarkResponse());
                            } catch (JsonProcessingException e) {
                                e.printStackTrace();
                            }

                            return generateApiGatewayProxyResponse(
                                    400, OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
                        });
    }

    private TrustMarkResponse createTrustMarkResponse() {
        return new TrustMarkResponse(
                configurationService.getBaseURL().orElseThrow(),
                configurationService.getBaseURL().orElseThrow(),
                List.of(
                        AuthenticationValues.LOW_LEVEL,
                        AuthenticationValues.MEDIUM_LEVEL,
                        AuthenticationValues.HIGH_LEVEL,
                        AuthenticationValues.VERY_HIGH_LEVEL));
    }
}
