package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class VerifyCodeHandler extends BaseFrontendHandler<VerifyCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyCodeHandler.class);

    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final DynamoAccountModifiersService accountModifiersService;

    protected VerifyCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            DynamoAccountModifiersService accountModifiersService) {
        super(
                VerifyCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.accountModifiersService = accountModifiersService;
    }

    public VerifyCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    public VerifyCodeHandler(ConfigurationService configurationService) {
        super(VerifyCodeRequest.class, configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.accountModifiersService = new DynamoAccountModifiersService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            VerifyCodeRequest codeRequest,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getSession());

        try {
            LOG.info("Processing request");

            var session = userContext.getSession();
            var notificationType = codeRequest.getNotificationType();
            JourneyType journeyType;
            switch (notificationType) {
                case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                    journeyType = JourneyType.ACCOUNT_RECOVERY;
                    break;
                case MFA_SMS:
                    journeyType = JourneyType.SIGN_IN;
                    break;
                case RESET_PASSWORD_WITH_CODE:
                    journeyType = JourneyType.PASSWORD_RESET;
                    break;
                default:
                    journeyType = JourneyType.REGISTRATION;
                    break;
            }
            var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
            var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

            if (isCodeBlockedForSession(session, codeBlockedKeyPrefix)) {
                ErrorResponse errorResponse = blockedCodeBehaviour(codeRequest);
                return generateApiGatewayProxyErrorResponse(400, errorResponse);
            }

            var isTestClient = isTestClientWithAllowedEmail(userContext, configurationService);
            var code =
                    isTestClient
                            ? getOtpCodeForTestClient(notificationType)
                            : codeStorageService.getOtpCode(
                                    session.getEmailAddress(), notificationType);

            var errorResponse =
                    ValidationHelper.validateVerificationCode(
                            notificationType,
                            code,
                            codeRequest.getCode(),
                            codeStorageService,
                            session.getEmailAddress(),
                            configurationService.getCodeMaxRetries());

            if (errorResponse.stream().anyMatch(ErrorResponse.ERROR_1002::equals)) {
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }

            sessionService.save(session);

            if (errorResponse.isPresent()) {
                processBlockedCodeSession(
                        errorResponse.get(), session, codeRequest, input, userContext, journeyType);
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            processSuccessfulCodeRequest(session, codeRequest, input, userContext);

            return generateEmptySuccessApiGatewayResponse();
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private ErrorResponse blockedCodeBehaviour(VerifyCodeRequest codeRequest) {
        return Map.ofEntries(
                        entry(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, ErrorResponse.ERROR_1048),
                        entry(VERIFY_EMAIL, ErrorResponse.ERROR_1033),
                        entry(RESET_PASSWORD_WITH_CODE, ErrorResponse.ERROR_1039),
                        entry(MFA_SMS, ErrorResponse.ERROR_1027))
                .get(codeRequest.getNotificationType());
    }

    private boolean isCodeBlockedForSession(Session session, String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(
                session.getEmailAddress(), codeBlockedKeyPrefix);
    }

    private void blockCodeForSession(Session session, String codeBlockPrefix) {
        codeStorageService.saveBlockedForEmail(
                session.getEmailAddress(),
                codeBlockPrefix,
                configurationService.getBlockedEmailDuration());
        LOG.info("Email is blocked");
    }

    private void resetIncorrectMfaCodeAttemptsCount(Session session) {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(session.getEmailAddress());
        LOG.info("IncorrectMfaCodeAttemptsCount reset");
    }

    private void processSuccessfulCodeRequest(
            Session session,
            VerifyCodeRequest codeRequest,
            APIGatewayProxyRequestEvent input,
            UserContext userContext) {
        var notificationType = codeRequest.getNotificationType();
        var accountRecoveryJourney =
                codeRequest.getNotificationType().equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
        var metadataPairs =
                new AuditService.MetadataPair[] {
                    pair("notification-type", notificationType.name()),
                    pair("account-recovery", accountRecoveryJourney)
                };
        var clientSession = userContext.getClientSession();
        var clientId = userContext.getClient().get().getClientID();
        var levelOfConfidence =
                clientSession.getEffectiveVectorOfTrust().containsLevelOfConfidence()
                        ? clientSession.getEffectiveVectorOfTrust().getLevelOfConfidence()
                        : NONE;

        if (notificationType.equals(MFA_SMS)) {
            LOG.info(
                    "MFA code has been successfully verified for MFA type: {}. RegistrationJourney: {}",
                    MFAMethodType.SMS.getValue(),
                    false);
            sessionService.save(session.setVerifiedMfaMethodType(MFAMethodType.SMS));
            metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("notification-type", notificationType.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", accountRecoveryJourney)
                    };
            clearAccountRecoveryBlockIfPresent(userContext, input);
            cloudwatchMetricsService.incrementAuthenticationSuccess(
                    session.isNewAccount(),
                    clientId,
                    userContext.getClientName(),
                    levelOfConfidence.getValue(),
                    clientService.isTestJourney(clientId, session.getEmailAddress()),
                    true);
        }
        codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
        auditService.submitAuditEvent(
                FrontendAuditableEvent.CODE_VERIFIED,
                userContext.getClientSessionId(),
                session.getSessionId(),
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                session.getInternalCommonSubjectIdentifier(),
                session.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                extractPersistentIdFromHeaders(input.getHeaders()),
                metadataPairs);
    }

    private void processBlockedCodeSession(
            ErrorResponse errorResponse,
            Session session,
            VerifyCodeRequest codeRequest,
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            JourneyType journeyType) {
        var notificationType = codeRequest.getNotificationType();
        var accountRecoveryJourney = journeyType.equals(JourneyType.ACCOUNT_RECOVERY);
        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        var metadataPairs =
                new AuditService.MetadataPair[] {
                    pair("notification-type", notificationType.name()),
                    pair("account-recovery", accountRecoveryJourney)
                };
        if (notificationType.equals(MFA_SMS)) {
            metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("notification-type", notificationType.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", accountRecoveryJourney)
                    };
        }
        AuditableEvent auditableEvent;
        if (List.of(
                        ErrorResponse.ERROR_1027,
                        ErrorResponse.ERROR_1033,
                        ErrorResponse.ERROR_1039,
                        ErrorResponse.ERROR_1048)
                .contains(errorResponse)) {
            if (errorResponse.equals(ErrorResponse.ERROR_1027)
                    || errorResponse.equals(ErrorResponse.ERROR_1048)
                    || errorResponse.equals(ErrorResponse.ERROR_1039)) {
                blockCodeForSession(session, codeBlockedKeyPrefix);
            }
            resetIncorrectMfaCodeAttemptsCount(session);
            auditableEvent = FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
        } else {
            auditableEvent = FrontendAuditableEvent.INVALID_CODE_SENT;
        }
        auditService.submitAuditEvent(
                auditableEvent,
                userContext.getClientSessionId(),
                session.getSessionId(),
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                session.getInternalCommonSubjectIdentifier(),
                session.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                extractPersistentIdFromHeaders(input.getHeaders()),
                metadataPairs);
    }

    private Optional<String> getOtpCodeForTestClient(NotificationType notificationType) {
        LOG.info("Using TestClient with NotificationType {}", notificationType);
        switch (notificationType) {
            case VERIFY_EMAIL:
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
            case RESET_PASSWORD_WITH_CODE:
                return configurationService.getTestClientVerifyEmailOTP();
            case MFA_SMS:
                return configurationService.getTestClientVerifyPhoneNumberOTP();
            default:
                LOG.error(
                        "Invalid NotificationType: {} configured for TestClient", notificationType);
                throw new RuntimeException("Invalid NotificationType for use with TestClient");
        }
    }

    private void clearAccountRecoveryBlockIfPresent(
            UserContext userContext, APIGatewayProxyRequestEvent input) {
        var accountRecoveryBlockPresent =
                accountModifiersService.isAccountRecoveryBlockPresent(
                        userContext.getSession().getInternalCommonSubjectIdentifier());
        if (accountRecoveryBlockPresent) {
            LOG.info("AccountRecovery block is present. Removing block");
            accountModifiersService.removeAccountRecoveryBlockIfPresent(
                    userContext.getSession().getInternalCommonSubjectIdentifier());
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.ACCOUNT_RECOVERY_BLOCK_REMOVED,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    userContext.getSession().getInternalCommonSubjectIdentifier(),
                    userContext.getSession().getEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    extractPersistentIdFromHeaders(input.getHeaders()),
                    pair("mfa-type", MFAMethodType.SMS.getValue()));
        }
    }
}
