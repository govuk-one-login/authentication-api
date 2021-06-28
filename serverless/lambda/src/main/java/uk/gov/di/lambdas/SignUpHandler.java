package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SignupRequest;
import uk.gov.di.entity.SignupResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.PasswordValidation;

import java.util.Optional;
import java.util.Set;

import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class SignUpHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AuthenticationService authenticationService;
    private final ValidationService validationService;
    private final SessionService sessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SignUpHandler(
            AuthenticationService authenticationService,
            ValidationService validationService,
            SessionService sessionService) {
        this.authenticationService = authenticationService;
        this.validationService = validationService;
        this.sessionService = sessionService;
    }

    public SignUpHandler() {
        this.authenticationService = new UserService();
        this.validationService = new ValidationService();
        sessionService = new SessionService(new ConfigurationService());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }

        try {
            SignupRequest signupRequest =
                    objectMapper.readValue(input.getBody(), SignupRequest.class);

            Set<PasswordValidation> passwordValidationErrors =
                    validationService.validatePassword(signupRequest.getPassword());

            if (passwordValidationErrors.isEmpty()) {
                authenticationService.signUp(signupRequest.getEmail(), signupRequest.getPassword());

                sessionService.save(
                        session.get()
                                .setState(TWO_FACTOR_REQUIRED)
                                .setEmailAddress(signupRequest.getEmail()));
                return generateApiGatewayProxyResponse(
                        200, new SignupResponse(session.get().getState()));
            } else {
                return generateApiGatewayProxyResponse(400, passwordValidationErrors.toString());
            }
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
