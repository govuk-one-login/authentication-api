package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.UpdateProfileRequest;
import uk.gov.di.entity.UpdateProfileResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.SessionService;

import java.util.Optional;

import static uk.gov.di.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UpdateProfileHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UpdateProfileHandler(
            AuthenticationService authenticationService, SessionService sessionService) {
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
    }

    public UpdateProfileHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        sessionService = new SessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        try {
            UpdateProfileRequest profileRequest =
                    objectMapper.readValue(input.getBody(), UpdateProfileRequest.class);
            if (!session.get().validateSession(profileRequest.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            switch (profileRequest.getUpdateProfileType()) {
                case UPDATE_PHONE_NUMBER:
                    authenticationService.updatePhoneNumber(
                            profileRequest.getEmail(), profileRequest.getProfileInformation());

                    return generateApiGatewayProxyResponse(
                            200,
                            new UpdateProfileResponse(
                                    session.get()
                                            .setState(ADDED_UNVERIFIED_PHONE_NUMBER)
                                            .getState()));
            }
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1013);
    }
}
