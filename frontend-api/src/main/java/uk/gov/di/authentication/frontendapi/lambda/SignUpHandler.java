package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_CREATED_A_PASSWORD;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class SignUpHandler extends BaseFrontendHandler<SignupRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(SignUpHandler.class);

    private final ValidationService validationService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public SignUpHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            ValidationService validationService) {
        super(
                SignupRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.validationService = validationService;
    }

    public SignUpHandler() {
        super(SignupRequest.class, ConfigurationService.getInstance());
        this.validationService = new ValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            SignupRequest request,
            UserContext userContext) {
        try {
            var nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(), USER_HAS_CREATED_A_PASSWORD);

            SignupRequest signupRequest =
                    objectMapper.readValue(input.getBody(), SignupRequest.class);

            Optional<ErrorResponse> passwordValidationErrors =
                    validationService.validatePassword(signupRequest.getPassword());

            if (passwordValidationErrors.isEmpty()) {
                if (authenticationService.userExists(signupRequest.getEmail())) {
                    LOG.error("User with email {} already exists", signupRequest.getEmail());
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
                }
                authenticationService.signUp(
                        signupRequest.getEmail(),
                        signupRequest.getPassword(),
                        new Subject(),
                        new TermsAndConditions(
                                configurationService.getTermsAndConditionsVersion(),
                                LocalDateTime.now(ZoneId.of("UTC")).toString()));

                sessionService.save(
                        userContext
                                .getSession()
                                .setState(nextState)
                                .setEmailAddress(signupRequest.getEmail()));

                LOG.info(
                        "SignUpHandler successfully processed request for session {}",
                        userContext.getSession().getSessionId());

                return generateApiGatewayProxyResponse(
                        200, new BaseAPIResponse(userContext.getSession().getState()));
            } else {
                return generateApiGatewayProxyErrorResponse(400, passwordValidationErrors.get());
            }
        } catch (JsonProcessingException e) {
            LOG.error("Error parsing request", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOG.error("Invalid transition in user journey", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
    }
}
