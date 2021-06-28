package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.CheckUserExistsResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.UserWithEmailRequest;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.EmailValidation;

import java.util.Optional;
import java.util.Set;

import static uk.gov.di.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class CheckUserExistsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private ValidationService validationService;
    private ObjectMapper objectMapper = new ObjectMapper();
    private AuthenticationService authenticationService;
    private final SessionService sessionService;

    public CheckUserExistsHandler(
            ValidationService validationService,
            AuthenticationService authenticationService,
            SessionService sessionService) {
        this.validationService = validationService;
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
    }

    public CheckUserExistsHandler() {
        this.validationService = new ValidationService();
        this.authenticationService = new UserService();
        this.sessionService = new SessionService(new ConfigurationService());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            Optional<Session> session =
                    sessionService.getSessionFromRequestHeaders(input.getHeaders());
            if (session.isPresent()) {
                session.get().setState(USER_NOT_FOUND);
                UserWithEmailRequest userExistsRequest =
                        objectMapper.readValue(input.getBody(), UserWithEmailRequest.class);
                String emailAddress = userExistsRequest.getEmail();
                Set<EmailValidation> emailErrors =
                        validationService.validateEmailAddress(emailAddress);
                if (!emailErrors.isEmpty()) {
                    return generateApiGatewayProxyResponse(400, emailErrors.toString());
                }
                boolean userExists = authenticationService.userExists(emailAddress);
                session.get().setEmailAddress(emailAddress);
                if (userExists) {
                    session.get().setState(AUTHENTICATION_REQUIRED);
                }
                CheckUserExistsResponse checkUserExistsResponse =
                        new CheckUserExistsResponse(
                                emailAddress, userExists, session.get().getState());
                String checkUserExistsResponseString =
                        objectMapper.writeValueAsString(checkUserExistsResponse);
                sessionService.save(session.get());

                return generateApiGatewayProxyResponse(200, checkUserExistsResponseString);
            }
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
