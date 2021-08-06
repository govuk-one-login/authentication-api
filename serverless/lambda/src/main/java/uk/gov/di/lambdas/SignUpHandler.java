package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SignupRequest;
import uk.gov.di.helpers.StateMachine.InvalidStateTransitionException;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;

import java.util.Optional;

import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.helpers.StateMachine.validateStateTransition;

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
        ConfigurationService configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.validationService = new ValidationService();
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
            validateStateTransition(session.get(), TWO_FACTOR_REQUIRED);

            SignupRequest signupRequest =
                    objectMapper.readValue(input.getBody(), SignupRequest.class);

            Optional<ErrorResponse> passwordValidationErrors =
                    validationService.validatePassword(signupRequest.getPassword());

            if (passwordValidationErrors.isEmpty()) {
                if (authenticationService.userExists(signupRequest.getEmail())) {
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
                }
                authenticationService.signUp(
                        signupRequest.getEmail(), signupRequest.getPassword(), new Subject());

                sessionService.save(
                        session.get()
                                .setState(TWO_FACTOR_REQUIRED)
                                .setEmailAddress(signupRequest.getEmail()));
                return generateApiGatewayProxyResponse(
                        200, new BaseAPIResponse(session.get().getState()));
            } else {
                return generateApiGatewayProxyErrorResponse(400, passwordValidationErrors.get());
            }
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1019);
        }
    }
}
