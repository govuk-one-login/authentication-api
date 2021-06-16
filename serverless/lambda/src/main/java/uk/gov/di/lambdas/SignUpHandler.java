package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.SignupRequest;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.PasswordValidation;

import java.util.Set;

public class SignUpHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private AuthenticationService authenticationService;
    private ValidationService validationService;
    private ObjectMapper objectMapper = new ObjectMapper();

    public SignUpHandler(
            AuthenticationService authenticationService, ValidationService validationService) {
        this.authenticationService = authenticationService;
        this.validationService = validationService;
    }

    public SignUpHandler() {
        this.authenticationService = new UserService();
        this.validationService = new ValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        LambdaLogger logger = context.getLogger();

        try {
            SignupRequest signupRequest =
                    objectMapper.readValue(input.getBody(), SignupRequest.class);

            Set<PasswordValidation> passwordValidationErrors =
                    validationService.validatePassword(signupRequest.getPassword());

            if (passwordValidationErrors.isEmpty()) {
                authenticationService.signUp(signupRequest.getEmail(), signupRequest.getPassword());
                apiGatewayProxyResponseEvent.setStatusCode(200);
            } else {
                apiGatewayProxyResponseEvent.setStatusCode(400);
                apiGatewayProxyResponseEvent.setBody(passwordValidationErrors.toString());
            }
            return apiGatewayProxyResponseEvent;
        } catch (JsonProcessingException e) {
            apiGatewayProxyResponseEvent.setStatusCode(400);
            apiGatewayProxyResponseEvent.setBody("Request is missing parameters");
            return apiGatewayProxyResponseEvent;
        }
    }
}
