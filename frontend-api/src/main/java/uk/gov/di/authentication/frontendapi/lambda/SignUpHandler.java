package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
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

    private static final Logger LOG = LogManager.getLogger(SignUpHandler.class);

    private final ValidationService validationService;
    private final AuditService auditService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public SignUpHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            ValidationService validationService,
            AuditService auditService) {
        super(
                SignupRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public SignUpHandler() {
        this(ConfigurationService.getInstance());
    }

    public SignUpHandler(ConfigurationService configurationService) {
        super(SignupRequest.class, configurationService);
        this.validationService = new ValidationService();
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            SignupRequest request,
            UserContext userContext) {
        try {
            LOG.info(
                    "SignUpHandler received request for session: {}",
                    userContext.getSession().getSessionId());
            var nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(),
                            USER_HAS_CREATED_A_PASSWORD,
                            userContext);

            Optional<ErrorResponse> passwordValidationErrors =
                    validationService.validatePassword(request.getPassword());

            if (passwordValidationErrors.isEmpty()) {
                if (authenticationService.userExists(request.getEmail())) {

                    auditService.submitAuditEvent(
                            FrontendAuditableEvent.CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
                            context.getAwsRequestId(),
                            userContext.getSession().getSessionId(),
                            userContext
                                    .getClient()
                                    .map(ClientRegistry::getClientID)
                                    .orElse(AuditService.UNKNOWN),
                            AuditService.UNKNOWN,
                            request.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

                    LOG.info(
                            "User already exists for session: {}",
                            userContext.getSession().getSessionId());
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
                }
                authenticationService.signUp(
                        request.getEmail(),
                        request.getPassword(),
                        new Subject(),
                        new TermsAndConditions(
                                configurationService.getTermsAndConditionsVersion(),
                                LocalDateTime.now(ZoneId.of("UTC")).toString()));

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

                sessionService.save(
                        userContext
                                .getSession()
                                .setState(nextState)
                                .setEmailAddress(request.getEmail()));

                LOG.info(
                        "SignUpHandler successfully processed request for session: {}",
                        userContext.getSession().getSessionId());
                return generateApiGatewayProxyResponse(
                        200, new BaseAPIResponse(userContext.getSession().getState()));
            } else {
                LOG.info(
                        "Invalid Password entered with errors: {}", passwordValidationErrors.get());
                return generateApiGatewayProxyErrorResponse(400, passwordValidationErrors.get());
            }
        } catch (JsonProcessingException e) {
            LOG.error(
                    "Error parsing request for session: {}",
                    userContext.getSession().getSessionId());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
    }
}
