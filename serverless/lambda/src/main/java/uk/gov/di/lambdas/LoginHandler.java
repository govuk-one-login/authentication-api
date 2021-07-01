package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.LoginRequest;
import uk.gov.di.entity.LoginResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.SessionService;

import java.util.Optional;

import static uk.gov.di.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class LoginHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public LoginHandler(
            SessionService sessionService, AuthenticationService authenticationService) {
        this.sessionService = sessionService;
        this.authenticationService = authenticationService;
    }

    public LoginHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }

        try {
            LoginRequest loginRequest = objectMapper.readValue(input.getBody(), LoginRequest.class);
            boolean userHasAccount = authenticationService.userExists(loginRequest.getEmail());
            if (!userHasAccount) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
            }
            boolean hasValidCredentials =
                    authenticationService.login(
                            loginRequest.getEmail(), loginRequest.getPassword());
            if (!hasValidCredentials) {
                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1008);
            }
            sessionService.save(session.get().setState(AUTHENTICATED));
            return generateApiGatewayProxyResponse(
                    200, new LoginResponse(session.get().getState()));
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
