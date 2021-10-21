package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.BaseFrontendRequest;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1000;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1014;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_MFA_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class MfaHandler extends BaseFrontendHandler<MfaRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaHandler.class);

    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AwsSqsClient sqsClient;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public MfaHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient) {
        super(
                MfaRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.sqsClient = sqsClient;
    }

    public MfaHandler() {
        super(MfaRequest.class, ConfigurationService.getInstance());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            MfaRequest request,
            UserContext userContext) {
        try {
            LOGGER.info(
                    "MfaHandler received request for session: {}",
                    userContext.getSession().getSessionId());

            var nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(), SYSTEM_HAS_SENT_MFA_CODE);

            BaseFrontendRequest userWithEmailRequest =
                    objectMapper.readValue(input.getBody(), BaseFrontendRequest.class);
            boolean codeRequestValid =
                    validateCodeRequestAttempts(
                            userWithEmailRequest.getEmail(), userContext.getSession());
            if (!codeRequestValid) {
                return generateApiGatewayProxyResponse(
                        400, new BaseAPIResponse(userContext.getSession().getState()));
            }
            if (!userContext.getSession().validateSession(userWithEmailRequest.getEmail())) {
                LOGGER.error(
                        "Email in session: {} does not match Email in Request",
                        userContext.getSession().getSessionId());
                return generateApiGatewayProxyErrorResponse(400, ERROR_1000);
            }
            String phoneNumber =
                    authenticationService
                            .getPhoneNumber(userWithEmailRequest.getEmail())
                            .orElse(null);

            if (phoneNumber == null) {
                LOGGER.error(
                        "PhoneNumber is null for session: {}",
                        userContext.getSession().getSessionId());
                return generateApiGatewayProxyErrorResponse(400, ERROR_1014);
            }
            String code = codeGeneratorService.sixDigitCode();
            codeStorageService.saveOtpCode(
                    userWithEmailRequest.getEmail(),
                    code,
                    configurationService.getCodeExpiry(),
                    MFA_SMS);
            sessionService.save(
                    userContext.getSession().setState(nextState).incrementCodeRequestCount());
            NotifyRequest notifyRequest = new NotifyRequest(phoneNumber, MFA_SMS, code);
            if (!isTestClientAndAllowedEmail(userContext, MFA_SMS)) {
                sqsClient.send(objectMapper.writeValueAsString(notifyRequest));
            }
            LOGGER.info(
                    "MfaHandler successfully processed request for session: {}",
                    userContext.getSession().getSessionId());

            return generateApiGatewayProxyResponse(
                    200, new BaseAPIResponse(userContext.getSession().getState()));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    "Request is missing parameters. session: {} Request Body: {}",
                    userContext.getSession().getSessionId(),
                    input.getBody());
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOGGER.error(
                    "Invalid transition in user journey for session: {}",
                    userContext.getSession().getSessionId(),
                    e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
        } catch (ClientNotFoundException e) {
            LOGGER.error(
                    "Client not found for session: {}", userContext.getSession().getSessionId(), e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private boolean validateCodeRequestAttempts(String email, Session session) {
        if (session.getCodeRequestCount() == configurationService.getCodeMaxRetries()) {
            LOGGER.info(
                    "User has requested too many OTP codes for session: {}",
                    session.getSessionId());
            codeStorageService.saveBlockedForEmail(
                    email, CODE_REQUEST_BLOCKED_KEY_PREFIX, configurationService.getCodeExpiry());
            SessionState nextState =
                    stateMachine.transition(session.getState(), SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES);
            sessionService.save(session.setState(nextState).resetCodeRequestCount());
            return false;
        }
        if (codeStorageService.isBlockedForEmail(email, CODE_REQUEST_BLOCKED_KEY_PREFIX)) {
            LOGGER.info(
                    "User is blocked from requesting any OTP codes for session: {}",
                    session.getSessionId());
            SessionState nextState =
                    stateMachine.transition(
                            session.getState(),
                            SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_MFA_VERIFICATION_CODES);
            sessionService.save(session.setState(nextState));
            return false;
        }
        return true;
    }

    private boolean isTestClientAndAllowedEmail(
            UserContext userContext, NotificationType notificationType)
            throws ClientNotFoundException {
        if (configurationService.isTestClientsEnabled()) {
            LOGGER.warn(
                    "TestClients are ENABLED: SessionId {}",
                    userContext.getSession().getSessionId());
        } else {
            return false;
        }
        String emailAddress = userContext.getSession().getEmailAddress();
        return userContext
                .getClient()
                .map(
                        clientRegistry -> {
                            if (clientRegistry.isTestClient()
                                    && clientRegistry
                                            .getTestClientEmailAllowlist()
                                            .contains(emailAddress)) {
                                LOGGER.info(
                                        "MfaHandler not sending message for TestClient {} {} email {} on TestClientEmailAllowlist with NotificationType {} for session {}",
                                        clientRegistry.getClientID(),
                                        clientRegistry.getClientName(),
                                        emailAddress,
                                        notificationType,
                                        userContext.getSession().getSessionId());
                                return true;
                            } else {
                                return false;
                            }
                        })
                .orElseThrow(() -> new ClientNotFoundException(userContext.getSession()));
    }
}
