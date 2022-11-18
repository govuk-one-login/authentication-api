package uk.gov.di.authentication.testservices.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class DeleteSyntheticsUserHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DeleteSyntheticsUserHandler.class);

    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;

    public DeleteSyntheticsUserHandler() {
        this(ConfigurationService.getInstance());
    }

    public DeleteSyntheticsUserHandler(
            AuthenticationService authenticationService,
            ConfigurationService configurationService) {
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
    }

    public DeleteSyntheticsUserHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        LOG.info("Request received to DeleteSyntheticsUserHandler");

        String email = configurationService.getSyntheticsUsers();
        if (email == null || email.isBlank()) {
            LOG.info("Synthetics user account not configured.");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1010);
        }

        return authenticationService
                .getUserProfileByEmailMaybe(email)
                .map(
                        userProfile -> {
                            authenticationService.removeAccount(userProfile.getEmail());
                            LOG.info("Synthetics user account removed.");

                            return generateApiGatewayProxyResponse(204, "");
                        })
                .orElseGet(
                        () -> {
                            LOG.info("Synthetics user account not found.");
                            return generateApiGatewayProxyErrorResponse(
                                    404, ErrorResponse.ERROR_1010);
                        });
    }
}
