package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.frontendapi.helpers.SessionHelper;
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
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueOrElse;
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
            var notificationType = codeRequest.notificationType();
            var journeyType = getJourneyType(codeRequest, notificationType);
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
                            journeyType,
                            code,
                            codeRequest.code(),
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
            if (codeRequestType.equals(CodeRequestType.PW_RESET_MFA_SMS)) {
                SessionHelper.updateSessionWithSubject(
                        userContext,
                        authenticationService,
                        configurationService,
                        sessionService,
                        session);
            }
            processSuccessfulCodeRequest(session, codeRequest, input, userContext, journeyType);

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
                .get(codeRequest.notificationType());
    }

    private boolean isCodeBlockedForSession(Session session, String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(
                session.getEmailAddress(), codeBlockedKeyPrefix);
    }

    private void blockCodeForSession(Session session, String codeBlockPrefix) {
        codeStorageService.saveBlockedForEmail(
                session.getEmailAddress(),
                codeBlockPrefix,
                configurationService.getLockoutDuration());
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
            UserContext userContext,
            JourneyType journeyType) {
        var notificationType = codeRequest.notificationType();
        var accountRecoveryJourney =
                codeRequest.notificationType().equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
        int loginFailureCount = session.getRetryCount();
        var metadataPairs =
                new AuditService.MetadataPair[] {
                    pair("notification-type", notificationType.name()),
                    pair("account-recovery", accountRecoveryJourney),
                    pair("journey-type", String.valueOf(journeyType))
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
                        pair("account-recovery", accountRecoveryJourney),
                        pair("loginFailureCount", loginFailureCount),
                        pair("MFACodeEntered", codeRequest.code()),
                        pair("journey-type", String.valueOf(journeyType))
                    };
            clearAccountRecoveryBlockIfPresent(session, userContext, input);
            cloudwatchMetricsService.incrementAuthenticationSuccess(
                    session.isNewAccount(),
                    clientId,
                    userContext.getClientName(),
                    levelOfConfidence.getValue(),
                    clientService.isTestJourney(clientId, session.getEmailAddress()),
                    true);
        }
        codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
        submitAuditEvent(
                session, input, userContext, FrontendAuditableEvent.CODE_VERIFIED, metadataPairs);
    }

    private void processBlockedCodeSession(
            ErrorResponse errorResponse,
            Session session,
            VerifyCodeRequest codeRequest,
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            JourneyType journeyType) {
        var notificationType = codeRequest.notificationType();
        var accountRecoveryJourney = journeyType.equals(JourneyType.ACCOUNT_RECOVERY);
        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        var metadataPairs =
                new AuditService.MetadataPair[] {
                    pair("notification-type", notificationType.name()),
                    pair("account-recovery", accountRecoveryJourney),
                    pair("journey-type", String.valueOf(journeyType))
                };
        int loginFailureCount = session.getRetryCount();
        if (notificationType.equals(MFA_SMS)) {
            metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("notification-type", notificationType.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", accountRecoveryJourney),
                        pair("loginFailureCount", loginFailureCount),
                        pair("MFACodeEntered", codeRequest.code()),
                        pair("MaxSmsCount", configurationService.getCodeMaxRetries()),
                        pair("journey-type", String.valueOf(journeyType))
                    };
        }
        AuditableEvent auditableEvent;
        switch (errorResponse) {
            case ERROR_1027:
            case ERROR_1039:
            case ERROR_1048:
                blockCodeForSession(session, codeBlockedKeyPrefix);
                resetIncorrectMfaCodeAttemptsCount(session);
                auditableEvent = FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
                break;
            case ERROR_1033:
                resetIncorrectMfaCodeAttemptsCount(session);
                auditableEvent = FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
                break;
            default:
                auditableEvent = FrontendAuditableEvent.INVALID_CODE_SENT;
                break;
        }
        submitAuditEvent(session, input, userContext, auditableEvent, metadataPairs);
    }

    private void submitAuditEvent(
            Session session,
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            AuditableEvent auditableEvent,
            AuditService.MetadataPair... metadataPairs) {
        String txmaAuditEncoded =
                getHeaderValueOrElse(input.getHeaders(), TXMA_AUDIT_ENCODED_HEADER, null);

        var restrictedSection =
                new AuditService.RestrictedSection(Optional.ofNullable(txmaAuditEncoded));

        auditService.submitAuditEvent(
                auditableEvent,
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                userContext.getClientSessionId(),
                session.getSessionId(),
                session.getInternalCommonSubjectIdentifier(),
                session.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                extractPersistentIdFromHeaders(input.getHeaders()),
                restrictedSection,
                metadataPairs);
    }

    private Optional<String> getOtpCodeForTestClient(NotificationType notificationType) {
        LOG.info("Using TestClient with NotificationType {}", notificationType);
        return switch (notificationType) {
            case VERIFY_EMAIL,
                    VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                    RESET_PASSWORD_WITH_CODE -> configurationService.getTestClientVerifyEmailOTP();
            case MFA_SMS -> configurationService.getTestClientVerifyPhoneNumberOTP();
            default -> {
                LOG.error(
                        "Invalid NotificationType: {} configured for TestClient", notificationType);
                throw new RuntimeException("Invalid NotificationType for use with TestClient");
            }
        };
    }

    private void clearAccountRecoveryBlockIfPresent(
            Session session, UserContext userContext, APIGatewayProxyRequestEvent input) {
        var accountRecoveryBlockPresent =
                accountModifiersService.isAccountRecoveryBlockPresent(
                        session.getInternalCommonSubjectIdentifier());
        if (accountRecoveryBlockPresent) {
            LOG.info("AccountRecovery block is present. Removing block");
            accountModifiersService.removeAccountRecoveryBlockIfPresent(
                    session.getInternalCommonSubjectIdentifier());
            submitAuditEvent(
                    session,
                    input,
                    userContext,
                    FrontendAuditableEvent.ACCOUNT_RECOVERY_BLOCK_REMOVED,
                    pair("mfa-type", MFAMethodType.SMS.getValue()));
        }
    }

    private JourneyType getJourneyType(
            VerifyCodeRequest codeRequest, NotificationType notificationType) {
        JourneyType journeyType;
        if (codeRequest.journeyType() != null) {
            journeyType = codeRequest.journeyType();
        } else {
            journeyType =
                    switch (notificationType) {
                        case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> JourneyType.ACCOUNT_RECOVERY;
                        case MFA_SMS -> JourneyType.SIGN_IN;
                        case RESET_PASSWORD_WITH_CODE -> JourneyType.PASSWORD_RESET;
                        default -> JourneyType.REGISTRATION;
                    };
        }
        return journeyType;
    }
}
