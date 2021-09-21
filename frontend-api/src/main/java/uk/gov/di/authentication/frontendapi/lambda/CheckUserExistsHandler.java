package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.entity.UserWithEmailRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_REGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class CheckUserExistsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(CheckUserExistsHandler.class);

    private final ValidationService validationService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public CheckUserExistsHandler(
            ValidationService validationService,
            AuthenticationService authenticationService,
            SessionService sessionService) {
        this.validationService = validationService;
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
    }

    public CheckUserExistsHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.validationService = new ValidationService();
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
                            try {
                                Optional<Session> session =
                                        sessionService.getSessionFromRequestHeaders(
                                                input.getHeaders());
                                if (session.isPresent()) {
                                    LOG.info(
                                            "CheckUserExistsHandler processing request for session {}",
                                            session.get().getSessionId());

                                    session.get()
                                            .setState(
                                                    stateMachine.transition(
                                                            session.get().getState(),
                                                            USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS));

                                    UserWithEmailRequest userExistsRequest =
                                            objectMapper.readValue(
                                                    input.getBody(), UserWithEmailRequest.class);
                                    String emailAddress = userExistsRequest.getEmail();
                                    Optional<ErrorResponse> errorResponse =
                                            validationService.validateEmailAddress(emailAddress);
                                    if (errorResponse.isPresent()) {
                                        LOG.error(
                                                "Encountered an error while processing request for session {}; errorResponse is {}",
                                                session.get().getSessionId(),
                                                errorResponse.get());
                                        return generateApiGatewayProxyErrorResponse(
                                                400, errorResponse.get());
                                    }
                                    boolean userExists =
                                            authenticationService.userExists(emailAddress);
                                    session.get().setEmailAddress(emailAddress);
                                    if (userExists) {
                                        session.get()
                                                .setState(
                                                        stateMachine.transition(
                                                                session.get().getState(),
                                                                USER_ENTERED_REGISTERED_EMAIL_ADDRESS));
                                    }
                                    CheckUserExistsResponse checkUserExistsResponse =
                                            new CheckUserExistsResponse(
                                                    emailAddress,
                                                    userExists,
                                                    session.get().getState());
                                    sessionService.save(session.get());

                                    LOG.info(
                                            "CheckUserExistsHandler successfully processed request for session {}",
                                            session.get().getSessionId());

                                    return generateApiGatewayProxyResponse(
                                            200, checkUserExistsResponse);
                                } else {
                                    LOG.error("Session cannot be found");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1000);
                                }
                            } catch (JsonProcessingException e) {
                                LOG.error("Error parsing request", e);
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            } catch (StateMachine.InvalidStateTransitionException e) {
                                LOG.error("Invalid transition in user journey", e);
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1017);
                            }
                        });
    }
}
