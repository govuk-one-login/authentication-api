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
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.SessionAction.*;
import static uk.gov.di.authentication.shared.entity.SessionState.ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class LoginHandler extends BaseFrontendHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginHandler.class);
    private final CodeStorageService codeStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public LoginHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            AuthenticationService authenticationService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            CodeStorageService codeStorageService) {
        super(
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
    }

    public LoginHandler() {
        super(ConfigurationService.getInstance());
        this.codeStorageService =
                new CodeStorageService(
                        new RedisConnectionService(ConfigurationService.getInstance()));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input, Context context, UserContext userContext) {
        LOGGER.info("Request received to the LoginHandler");
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            LOGGER.error("Unable to find session");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        } else {
            LOGGER.info("LoginHandler processing session with ID {}", session.get().getSessionId());
        }

        try {
            LoginRequest loginRequest = objectMapper.readValue(input.getBody(), LoginRequest.class);
            boolean userHasAccount = authenticationService.userExists(loginRequest.getEmail());
            if (!userHasAccount) {
                LOGGER.error("The user does not have an account");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
            }

            SessionState currentState = session.get().getState();
            boolean keyExists =
                    codeStorageService.hasEnteredPasswordIncorrectBefore(loginRequest.getEmail());

            if (!keyExists && currentState.equals(ACCOUNT_TEMPORARILY_LOCKED)) {
                var nextState =
                        stateMachine.transition(
                                session.get().getState(), ACCOUNT_LOCK_EXPIRED, userContext);
                sessionService.save(session.get().setState(nextState));
            }

            boolean hasValidCredentials =
                    authenticationService.login(
                            loginRequest.getEmail(), loginRequest.getPassword());

            boolean hasEnteredPasswordIncorrectBefore =
                    codeStorageService.hasEnteredPasswordIncorrectBefore(loginRequest.getEmail());

            if (!hasValidCredentials) {
                if (hasEnteredPasswordIncorrectBefore) {
                    int count =
                            codeStorageService.getIncorrectPasswordCount(loginRequest.getEmail());

                    if (count >= configurationService.getMaxPasswordRetries()) {
                        if (!session.get().getState().equals(ACCOUNT_TEMPORARILY_LOCKED)) {
                            var nextState =
                                    stateMachine.transition(
                                            session.get().getState(),
                                            USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES,
                                            userContext);
                            sessionService.save(session.get().setState(nextState));
                        }

                        return generateApiGatewayProxyResponse(
                                200, new LoginResponse(null, session.get().getState()));
                    } else {
                        codeStorageService.increaseIncorrectPasswordCount(
                                loginRequest.getEmail(), count);
                    }
                } else {
                    codeStorageService.createIncorrectPasswordCount(loginRequest.getEmail());
                }

                LOGGER.error("Invalid login credentials entered");
                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1008);
            }

            if (hasEnteredPasswordIncorrectBefore) {
                codeStorageService.deleteIncorrectPasswordCount(loginRequest.getEmail());
            }

            var nextState =
                    stateMachine.transition(
                            session.get().getState(), USER_ENTERED_VALID_CREDENTIALS, userContext);
            sessionService.save(session.get().setState(nextState));
            if (nextState.equals(TWO_FACTOR_REQUIRED)) {
                return generateApiGatewayProxyResponse(
                        200, new BaseAPIResponse(session.get().getState()));
            }
            String phoneNumber =
                    authenticationService.getPhoneNumber(loginRequest.getEmail()).orElseThrow();

            String concatPhoneNumber = RedactPhoneNumberHelper.redactPhoneNumber(phoneNumber);

            LOGGER.info(
                    "User has successfully Logged in. Generating successful LoginResponse for session with ID {}",
                    session.get().getSessionId());
            return generateApiGatewayProxyResponse(
                    200, new LoginResponse(concatPhoneNumber, session.get().getState()));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    "Request is missing parameters. The body present in request: {}",
                    input.getBody());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOGGER.error("Invalid transition in user journey. Unable to Login user", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
    }
}
