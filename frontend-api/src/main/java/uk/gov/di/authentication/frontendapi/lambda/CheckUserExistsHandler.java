package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_REGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class CheckUserExistsHandler extends BaseFrontendHandler<CheckUserExistsRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(CheckUserExistsHandler.class);

    private final ValidationService validationService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public CheckUserExistsHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            ValidationService validationService) {
        super(
                CheckUserExistsRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.validationService = validationService;
    }

    public CheckUserExistsHandler() {
        super(CheckUserExistsRequest.class, ConfigurationService.getInstance());
        this.validationService = new ValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            CheckUserExistsRequest request,
            UserContext userContext) {
        try {
            LOG.info(
                    "CheckUserExistsHandler processing request for session {}",
                    userContext.getSession().getSessionId());

            userContext
                    .getSession()
                    .setState(
                            stateMachine.transition(
                                    userContext.getSession().getState(),
                                    USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS,
                                    userContext));

            String emailAddress = request.getEmail();
            Optional<ErrorResponse> errorResponse =
                    validationService.validateEmailAddress(emailAddress);
            if (errorResponse.isPresent()) {
                LOG.error(
                        "Encountered an error while processing request for session {}; errorResponse is {}",
                        userContext.getSession().getSessionId(),
                        errorResponse.get());
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            boolean userExists = authenticationService.userExists(emailAddress);
            userContext.getSession().setEmailAddress(emailAddress);
            if (userExists) {
                userContext
                        .getSession()
                        .setState(
                                stateMachine.transition(
                                        userContext.getSession().getState(),
                                        USER_ENTERED_REGISTERED_EMAIL_ADDRESS,
                                        userContext));
            }
            CheckUserExistsResponse checkUserExistsResponse =
                    new CheckUserExistsResponse(
                            emailAddress, userExists, userContext.getSession().getState());
            sessionService.save(userContext.getSession());

            LOG.info(
                    "CheckUserExistsHandler successfully processed request for session {}",
                    userContext.getSession().getSessionId());

            return generateApiGatewayProxyResponse(200, checkUserExistsResponse);

        } catch (JsonProcessingException e) {
            LOG.error("Error parsing UserInfo request", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOG.error("Invalid transition in user journey", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
    }
}
