package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Locale;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1000;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1014;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_MFA_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class MfaHandler extends BaseFrontendHandler<MfaRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MfaHandler.class);

    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
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
            AuditService auditService,
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
        this.auditService = auditService;
        this.sqsClient = sqsClient;
    }

    public MfaHandler() {
        super(MfaRequest.class, ConfigurationService.getInstance());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService(configurationService);
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
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

            attachSessionIdToLogs(userContext.getSession().getSessionId());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);
            attachLogFieldToLogs(
                    CLIENT_ID,
                    userContext.getClient().map(ClientRegistry::getClientID).orElse("unknown"));

            LOG.info("MfaHandler received request");

            String email = request.getEmail().toLowerCase(Locale.ROOT);
            boolean codeRequestValid = validateCodeRequestAttempts(email, userContext);
            if (!codeRequestValid) {
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.MFA_INVALID_CODE_REQUEST,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        email,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);

                return generateApiGatewayProxyResponse(
                        400, new BaseAPIResponse(userContext.getSession().getState()));
            }

            if (!userContext.getSession().validateSession(email)) {
                LOG.warn("Email does not match Email in Request");

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.MFA_MISMATCHED_EMAIL,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        email,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);

                return generateApiGatewayProxyErrorResponse(400, ERROR_1000);
            }
            String phoneNumber = authenticationService.getPhoneNumber(email).orElse(null);

            if (phoneNumber == null) {
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.MFA_MISSING_PHONE_NUMBER,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        email,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);

                return generateApiGatewayProxyErrorResponse(400, ERROR_1014);
            }

            var nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(),
                            SYSTEM_HAS_SENT_MFA_CODE,
                            userContext);

            String code = codeGeneratorService.sixDigitCode();
            codeStorageService.saveOtpCode(
                    email, code, configurationService.getCodeExpiry(), MFA_SMS);
            sessionService.save(
                    userContext.getSession().setState(nextState).incrementCodeRequestCount());
            NotifyRequest notifyRequest = new NotifyRequest(phoneNumber, MFA_SMS, code);
            if (!isTestClientAndAllowedEmail(userContext, MFA_SMS)) {
                sqsClient.send(objectMapper.writeValueAsString(notifyRequest));

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        email,
                        IpAddressHelper.extractIpAddress(input),
                        phoneNumber,
                        persistentSessionId);
            } else {
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT_FOR_TEST_CLIENT,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        email,
                        IpAddressHelper.extractIpAddress(input),
                        phoneNumber,
                        persistentSessionId);
            }
            LOG.info("Successfully processed request");

            return generateApiGatewayProxyResponse(
                    200, new BaseAPIResponse(userContext.getSession().getState()));
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
        } catch (ClientNotFoundException e) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private boolean validateCodeRequestAttempts(String email, UserContext userContext) {
        Session session = userContext.getSession();
        if (session.getCodeRequestCount() == configurationService.getCodeMaxRetries()) {
            LOG.info("User has requested too many OTP codes");
            codeStorageService.saveBlockedForEmail(
                    email, CODE_REQUEST_BLOCKED_KEY_PREFIX, configurationService.getCodeExpiry());
            SessionState nextState =
                    stateMachine.transition(
                            session.getState(), SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES, userContext);
            sessionService.save(session.setState(nextState).resetCodeRequestCount());
            return false;
        }
        if (codeStorageService.isBlockedForEmail(email, CODE_REQUEST_BLOCKED_KEY_PREFIX)) {
            LOG.info("User is blocked from requesting any OTP codes");
            SessionState nextState =
                    stateMachine.transition(
                            session.getState(),
                            SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_MFA_VERIFICATION_CODES,
                            userContext);
            sessionService.save(session.setState(nextState));
            return false;
        }
        if (codeStorageService.isBlockedForEmail(email, CODE_BLOCKED_KEY_PREFIX)) {
            LOG.info("User is blocked from requesting any OTP codes");
            SessionState nextState =
                    stateMachine.transition(
                            session.getState(),
                            USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES,
                            userContext);
            sessionService.save(session.setState(nextState));
            return false;
        }
        return true;
    }

    private boolean isTestClientAndAllowedEmail(
            UserContext userContext, NotificationType notificationType)
            throws ClientNotFoundException {
        if (configurationService.isTestClientsEnabled()) {
            LOG.warn("TestClients are ENABLED");
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
                                LOG.info(
                                        "MfaHandler not sending message with NotificationType {}",
                                        notificationType);
                                return true;
                            } else {
                                return false;
                            }
                        })
                .orElseThrow(() -> new ClientNotFoundException(userContext.getSession()));
    }
}
