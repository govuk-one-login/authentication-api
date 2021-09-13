package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.helpers.RedactPhoneNumberHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class LoginHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginHandler.class);

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
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("Request received to the LoginHandler");
                            Optional<Session> session =
                                    sessionService.getSessionFromRequestHeaders(input.getHeaders());
                            if (session.isEmpty()) {
                                LOGGER.error("Unable to find session");
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1000);
                            } else {
                                LOGGER.info(
                                        "LoginHandler processing session with ID {}",
                                        session.get().getSessionId());
                            }

                            try {
                                StateMachine.validateStateTransition(
                                        session.get(), SessionState.LOGGED_IN);

                                LoginRequest loginRequest =
                                        objectMapper.readValue(input.getBody(), LoginRequest.class);
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
                                    LOGGER.error("Invalid login credentials entered");
                                    return generateApiGatewayProxyErrorResponse(
                                            401, ErrorResponse.ERROR_1008);
                                }
                                String phoneNumber =
                                        authenticationService
                                                .getPhoneNumber(loginRequest.getEmail())
                                                .orElse(null);

                                if (phoneNumber == null) {
                                    LOGGER.error(
                                            "No Phone Number has been registered for this user");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1014);
                                }
                                String concatPhoneNumber =
                                        RedactPhoneNumberHelper.redactPhoneNumber(phoneNumber);
                                sessionService.save(session.get().setState(SessionState.LOGGED_IN));
                                LOGGER.info(
                                        "User has successfully Logged in. Generating successful LoginResponse for session with ID {}",
                                        session.get().getSessionId());
                                return generateApiGatewayProxyResponse(
                                        200,
                                        new LoginResponse(
                                                concatPhoneNumber, session.get().getState()));
                            } catch (JsonProcessingException e) {
                                LOGGER.error(
                                        "Request is missing parameters. The body present in request: {}",
                                        input.getBody());
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            } catch (StateMachine.InvalidStateTransitionException e) {
                                LOGGER.error(
                                        "Invalid transition in user journey. Unable to Login user",
                                        e);
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1017);
                            }
                        });
    }
}
