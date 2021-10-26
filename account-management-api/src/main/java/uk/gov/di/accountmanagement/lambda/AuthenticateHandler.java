package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class AuthenticateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticateHandler.class);

    private final AuthenticationService authenticationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AuthenticateHandler(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public AuthenticateHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("Request received to the AuthenticateHandler");

                            try {
                                AuthenticateRequest loginRequest =
                                        objectMapper.readValue(
                                                input.getBody(), AuthenticateRequest.class);
                                boolean userHasAccount =
                                        authenticationService.userExists(loginRequest.getEmail());
                                if (!userHasAccount) {
                                    LOGGER.error("The user does not have an account");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1010);
                                }
                                boolean hasValidCredentials =
                                        authenticationService.login(
                                                loginRequest.getEmail(),
                                                loginRequest.getPassword());
                                if (!hasValidCredentials) {
                                    LOGGER.info("Invalid login credentials entered");
                                    return generateApiGatewayProxyErrorResponse(
                                            401, ErrorResponse.ERROR_1008);
                                }
                                LOGGER.info(
                                        "User has successfully Logged in. Generating successful AuthenticateResponse");
                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonProcessingException e) {
                                LOGGER.error(
                                        "Request is missing parameters. The body present in request: {}",
                                        input.getBody());
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
