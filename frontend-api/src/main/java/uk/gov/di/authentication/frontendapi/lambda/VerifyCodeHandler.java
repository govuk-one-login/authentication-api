package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.shared.domain.RequestHeaders;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.*;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class VerifyCodeHandler extends BaseFrontendHandler<VerifyCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(VerifyCodeHandler.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final CodeStorageService codeStorageService;
    private final ValidationService validationService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine;
    private final AuditService auditService;

    protected VerifyCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            ValidationService validationService,
            StateMachine<SessionState, SessionAction, UserContext> stateMachine,
            AuditService auditService) {
        super(
                VerifyCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.validationService = validationService;
        this.stateMachine = stateMachine;
        this.auditService = auditService;
    }

    public VerifyCodeHandler() {
        super(VerifyCodeRequest.class, ConfigurationService.getInstance());
        this.codeStorageService =
                new CodeStorageService(
                        new RedisConnectionService(ConfigurationService.getInstance()));
        this.validationService = new ValidationService();
        this.stateMachine = userJourneyStateMachine();
        this.auditService = new AuditService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            VerifyCodeRequest request,
            UserContext userContext) {
        try {
            LOG.info(
                    "VerifyCodeHandler processing request for session: {}",
                    userContext.getSession().getSessionId());

            VerifyCodeRequest codeRequest =
                    objectMapper.readValue(input.getBody(), VerifyCodeRequest.class);

            var session = userContext.getSession();

            if (isCodeBlockedForSession(session)) {
                sessionService.save(
                        session.setState(
                                stateMachine.transition(
                                        session.getState(),
                                        blockedCodeBehaviour(codeRequest),
                                        userContext)));
                return generateResponse(session);
            }

            var code =
                    configurationService.isTestClientsEnabled()
                            ? getOtpCode(userContext, codeRequest.getNotificationType())
                            : codeStorageService.getOtpCode(
                                    session.getEmailAddress(), codeRequest.getNotificationType());

            var validationAction =
                    validationService.validateVerificationCode(
                            codeRequest.getNotificationType(),
                            code,
                            codeRequest.getCode(),
                            session,
                            configurationService.getCodeMaxRetries());

            if (validationAction == null) {
                LOG.error(
                        "Encountered unexpected error while processing session: {}",
                        userContext.getSession().getSessionId());
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
            }

            sessionService.save(
                    session.setState(
                            stateMachine.transition(
                                    session.getState(), validationAction, userContext)));
            processCodeSessionState(
                    session,
                    codeRequest.getNotificationType(),
                    userContext.getClientSession(),
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            RequestHeaders.CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive()),
                    input,
                    context,
                    userContext);

            if (isSessionActionBadRequest(validationAction)) return generateResponse(session);

            return generateSuccessResponse(session);

        } catch (JsonProcessingException e) {
            LOG.error(
                    "Error parsing request for session: {}",
                    userContext.getSession().getSessionId());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        } catch (ClientNotFoundException e) {
            LOG.error("Client not found for session: {}", userContext.getSession().getSessionId());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private boolean isSessionActionBadRequest(SessionAction sessionAction) {
        List<SessionAction> badRequestActions =
                List.of(
                        USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES,
                        USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                        USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES,
                        USER_ENTERED_INVALID_MFA_CODE,
                        USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                        USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE);

        return badRequestActions.contains(sessionAction);
    }

    private SessionAction blockedCodeBehaviour(VerifyCodeRequest codeRequest) {
        return Map.ofEntries(
                        entry(
                                VERIFY_EMAIL,
                                USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES),
                        entry(
                                VERIFY_PHONE_NUMBER,
                                USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES),
                        entry(MFA_SMS, USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES))
                .get(codeRequest.getNotificationType());
    }

    private boolean isCodeBlockedForSession(Session session) {
        return codeStorageService.isBlockedForEmail(
                session.getEmailAddress(), CODE_BLOCKED_KEY_PREFIX);
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse(Session session)
            throws JsonProcessingException {
        LOG.info(
                "VerifyCodeHandler successfully processed request for session: {}",
                session.getSessionId());

        return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
    }

    private APIGatewayProxyResponseEvent generateResponse(Session session)
            throws JsonProcessingException {
        LOG.info(
                "VerifyCodeHandler failed to process request for session: {}",
                session.getSessionId());

        return generateApiGatewayProxyResponse(400, new BaseAPIResponse(session.getState()));
    }

    private void blockCodeForSessionAndResetCount(Session session) {
        codeStorageService.saveBlockedForEmail(
                session.getEmailAddress(),
                CODE_BLOCKED_KEY_PREFIX,
                configurationService.getCodeExpiry());
        sessionService.save(session.resetRetryCount());
    }

    private void processCodeSessionState(
            Session session,
            NotificationType notificationType,
            ClientSession clientSession,
            String clientSessionId,
            APIGatewayProxyRequestEvent input,
            Context context,
            UserContext userContext) {
        if (notificationType.equals(VERIFY_PHONE_NUMBER)
                && List.of(PHONE_NUMBER_CODE_VERIFIED, CONSENT_REQUIRED)
                        .contains(session.getState())) {

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.CODE_VERIFIED,
                    context.getAwsRequestId(),
                    session.getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    session.getEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    pair("notification-type", notificationType.name()));

            codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
            authenticationService.updatePhoneNumberVerifiedStatus(session.getEmailAddress(), true);
            clientSessionService.saveClientSession(
                    clientSessionId,
                    clientSession.setEffectiveVectorOfTrust(VectorOfTrust.getDefaults()));
            sessionService.save(
                    session.setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL));
        } else if (List.of(
                        EMAIL_CODE_VERIFIED,
                        MFA_CODE_VERIFIED,
                        UPDATED_TERMS_AND_CONDITIONS,
                        CONSENT_REQUIRED)
                .contains(session.getState())) {

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.CODE_VERIFIED,
                    context.getAwsRequestId(),
                    session.getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    session.getEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    pair("notification-type", notificationType.name()));

            codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
        } else if (List.of(
                        PHONE_NUMBER_CODE_MAX_RETRIES_REACHED,
                        EMAIL_CODE_MAX_RETRIES_REACHED,
                        MFA_CODE_MAX_RETRIES_REACHED)
                .contains(session.getState())) {

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                    context.getAwsRequestId(),
                    session.getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    session.getEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    pair("notification-type", notificationType.name()));

            blockCodeForSessionAndResetCount(session);
        }
    }

    private Optional<String> getOtpCode(UserContext userContext, NotificationType notificationType)
            throws ClientNotFoundException {
        LOG.warn("TestClients are ENABLED: session: {}", userContext.getSession().getSessionId());
        final String emailAddress = userContext.getSession().getEmailAddress();
        final Optional<String> generatedOTPCode =
                codeStorageService.getOtpCode(emailAddress, notificationType);

        return userContext
                .getClient()
                .map(
                        clientRegistry -> {
                            if (clientRegistry.isTestClient()
                                    && clientRegistry
                                            .getTestClientEmailAllowlist()
                                            .contains(emailAddress)) {
                                LOG.info(
                                        "Using TestClient {} {} on TestClientEmailAllowlist with NotificationType {} and session: {}",
                                        clientRegistry.getClientID(),
                                        clientRegistry.getClientName(),
                                        notificationType,
                                        userContext.getSession().getSessionId());
                                switch (notificationType) {
                                    case VERIFY_EMAIL:
                                        return configurationService.getTestClientVerifyEmailOTP();
                                    case VERIFY_PHONE_NUMBER:
                                        return configurationService
                                                .getTestClientVerifyPhoneNumberOTP();
                                    case MFA_SMS:
                                        return configurationService
                                                .getTestClientVerifyPhoneNumberOTP();
                                    default:
                                        LOG.info(
                                                "Returning the generated OTP for TestClient {} {} with NotificationType {} and session: {}",
                                                clientRegistry.getClientID(),
                                                clientRegistry.getClientName(),
                                                notificationType,
                                                userContext.getSession().getSessionId());
                                        return generatedOTPCode;
                                }
                            } else {
                                return generatedOTPCode;
                            }
                        })
                .orElseThrow(() -> new ClientNotFoundException(userContext.getSession()));
    }
}
