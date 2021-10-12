package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.helpers.RedactPhoneNumberHelper;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.SessionAction.ACCOUNT_LOCK_EXPIRED;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_CREDENTIALS;
import static uk.gov.di.authentication.shared.entity.SessionState.ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class LoginHandler extends BaseFrontendHandler<LoginRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginHandler.class);
    private final CodeStorageService codeStorageService;
    private final UserMigrationService userMigrationService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public LoginHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            AuthenticationService authenticationService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            CodeStorageService codeStorageService,
            UserMigrationService userMigrationService) {
        super(
                LoginRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.userMigrationService = userMigrationService;
    }

    public LoginHandler() {
        super(LoginRequest.class, ConfigurationService.getInstance());
        this.codeStorageService =
                new CodeStorageService(
                        new RedisConnectionService(ConfigurationService.getInstance()));
        this.userMigrationService =
                new UserMigrationService(
                        new DynamoService(ConfigurationService.getInstance()),
                        ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            LoginRequest request,
            UserContext userContext) {
        LOGGER.info("Request received to the LoginHandler");
        try {
            LoginRequest loginRequest = objectMapper.readValue(input.getBody(), LoginRequest.class);
            UserProfile userProfile =
                    authenticationService.getUserProfileByEmail(loginRequest.getEmail());

            if (Objects.isNull(userProfile)) {
                LOGGER.error("The user does not have an account");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
            }

            SessionState currentState = userContext.getSession().getState();
            int incorrectPasswordCount =
                    codeStorageService.getIncorrectPasswordCount(loginRequest.getEmail());

            if (incorrectPasswordCount >= configurationService.getMaxPasswordRetries()) {
                LOGGER.info("User has exceeded max password retries");
                var nextState =
                        stateMachine.transition(
                                userContext.getSession().getState(),
                                USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES,
                                userContext);
                sessionService.save(userContext.getSession().setState(nextState));
                return generateApiGatewayProxyResponse(
                        200, new LoginResponse(null, userContext.getSession().getState()));
            }

            if (incorrectPasswordCount == 0 && currentState.equals(ACCOUNT_TEMPORARILY_LOCKED)) {
                var nextState =
                        stateMachine.transition(
                                userContext.getSession().getState(),
                                ACCOUNT_LOCK_EXPIRED,
                                userContext);
                sessionService.save(userContext.getSession().setState(nextState));
            }

            boolean userIsAMigratedUser =
                    userMigrationService.userHasBeenPartlyMigrated(
                            userProfile.getLegacySubjectID(), loginRequest.getEmail());
            boolean hasValidCredentials;
            if (userIsAMigratedUser) {
                LOGGER.info(
                        "Processing migrated user for sessionId {}",
                        userContext.getSession().getSessionId());
                hasValidCredentials =
                        userMigrationService.processMigratedUser(
                                loginRequest.getEmail(), loginRequest.getPassword());
            } else {
                hasValidCredentials =
                        authenticationService.login(
                                loginRequest.getEmail(), loginRequest.getPassword());
            }

            if (!hasValidCredentials) {
                codeStorageService.increaseIncorrectPasswordCount(loginRequest.getEmail());
                LOGGER.error(
                        "Invalid login credentials entered for sessionId {}",
                        userContext.getSession().getSessionId());
                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1008);
            }

            if (incorrectPasswordCount != 0) {
                codeStorageService.deleteIncorrectPasswordCount(loginRequest.getEmail());
            }

            var nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(),
                            USER_ENTERED_VALID_CREDENTIALS,
                            userContext);
            sessionService.save(userContext.getSession().setState(nextState));
            if (nextState.equals(TWO_FACTOR_REQUIRED)) {
                return generateApiGatewayProxyResponse(
                        200, new BaseAPIResponse(userContext.getSession().getState()));
            }
            String phoneNumber = userProfile.getPhoneNumber();

            String concatPhoneNumber = RedactPhoneNumberHelper.redactPhoneNumber(phoneNumber);

            LOGGER.info(
                    "User has successfully Logged in. Generating successful LoginResponse for session with ID {}",
                    userContext.getSession().getSessionId());
            return generateApiGatewayProxyResponse(
                    200, new LoginResponse(concatPhoneNumber, userContext.getSession().getState()));
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
