package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.CheckUserExistsRequest;
import uk.gov.di.entity.CheckUserExistsResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.EmailValidation;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class CheckUserExistsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private ValidationService validationService;
    private ObjectMapper objectMapper = new ObjectMapper();
    private AuthenticationService authenticationService;

    public CheckUserExistsHandler(
            ValidationService validationService, AuthenticationService authenticationService) {
        this.validationService = validationService;
        this.authenticationService = authenticationService;
    }

    public CheckUserExistsHandler() {
        this.validationService = new ValidationService();
        this.authenticationService = new UserService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            Optional<Map<String, String>> headers = Optional.ofNullable(input.getHeaders());
            if (headers.isEmpty() || !headers.get().containsKey("Session-Id")) {
                return generateApiGatewayProxyResponse(400, "Session-Id is missing");
            }

            CheckUserExistsRequest userExistsRequest =
                    objectMapper.readValue(input.getBody(), CheckUserExistsRequest.class);
            Set<EmailValidation> emailErrors =
                    validationService.validateEmailAddress(userExistsRequest.getEmail());
            if (!emailErrors.isEmpty()) {
                return generateApiGatewayProxyResponse(400, emailErrors.toString());
            }
            boolean userExists = authenticationService.userExists(userExistsRequest.getEmail());
            if (userExists) {
                CheckUserExistsResponse checkUserExistsResponse =
                        new CheckUserExistsResponse(userExistsRequest.getEmail(), true);
                String checkUserExistsResponseString =
                        objectMapper.writeValueAsString(checkUserExistsResponse);
                return generateApiGatewayProxyResponse(200, checkUserExistsResponseString);
            } else {
                CheckUserExistsResponse checkUserExistsResponse =
                        new CheckUserExistsResponse(userExistsRequest.getEmail(), false);
                String checkUserExistsResponseString =
                        objectMapper.writeValueAsString(checkUserExistsResponse);
                return generateApiGatewayProxyResponse(200, checkUserExistsResponseString);
            }
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyResponse(400, "Request is missing parameters");
        }
    }

    private APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, String body) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);
        return apiGatewayProxyResponseEvent;
    }
}
