package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AMCCallbackRequest;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AMCCallbackHandler extends BaseFrontendHandler<AMCCallbackRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AMCCallbackHandler.class);

    public AMCCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public AMCCallbackHandler(ConfigurationService configurationService) {
        super(AMCCallbackRequest.class, configurationService, true);
    }

    public AMCCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService) {
        super(
                AMCCallbackRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
    }

    @SuppressWarnings("java:S1185")
    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            AMCCallbackRequest request,
            UserContext userContext) {

        LOG.info("Request received to AMCCallbackHandler");
        return generateApiGatewayProxyResponse(200, "very cool");
    }
}
