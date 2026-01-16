package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.StartPasskeyAssertionRequest;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class StartPasskeyAssertionHandler extends BaseFrontendHandler<StartPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartPasskeyAssertionHandler.class);

    public StartPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public StartPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService) {
        super(
                StartPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
    }

    public StartPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(StartPasskeyAssertionRequest.class, configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            StartPasskeyAssertionRequest request,
            UserContext userContext) {
        LOG.info("StartPasskeyAssertionHandler called");
        return generateApiGatewayProxyResponse(200, "");
    }
}
