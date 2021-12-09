package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.services.AuthorisationResponseService;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class IPVCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final AuthorisationResponseService responseService;

    public IPVCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService,
            AuthorisationResponseService responseService) {
        this.configurationService = configurationService;
        this.responseService = responseService;
    }

    public IPVCallbackHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.responseService = new AuthorisationResponseService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to IPVCallbackHandler");
                            Optional<ErrorObject> errorObject =
                                    responseService.validateResponse(
                                            input.getQueryStringParameters());
                            if (errorObject.isPresent()) {
                                LOG.error("Error in IPV AuthorisationResponse");
                                // TODO - Do something with this error object
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        buildRedirectUri()));
                            }
                            return new APIGatewayProxyResponseEvent()
                                    .withStatusCode(302)
                                    .withHeaders(
                                            Map.of(ResponseHeaders.LOCATION, buildRedirectUri()));
                        });
    }

    private String buildRedirectUri() {
        URIBuilder redirectUriBuilder = new URIBuilder(configurationService.getLoginURI());
        try {
            return redirectUriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException();
        }
    }
}
