package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.frontendapi.helpers.TestClientHelper;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
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
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class VerifyCodeHandler extends BaseFrontendHandler<VerifyCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyCodeHandler.class);

    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    protected VerifyCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService) {
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
    }

    public VerifyCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    public VerifyCodeHandler(ConfigurationService configurationService) {
        super(VerifyCodeRequest.class, configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            VerifyCodeRequest codeRequest,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getSession());
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));
        attachLogFieldToLogs(
                CLIENT_ID,
                userContext.getClient().map(ClientRegistry::getClientID).orElse("unknown"));

        try {
            LOG.info("Processing request");

            var session = userContext.getSession();

            if (isCodeBlockedForSession(session)) {
                ErrorResponse errorResponse = blockedCodeBehaviour(codeRequest);
                return generateApiGatewayProxyErrorResponse(400, errorResponse);
            }

            var isTestClient =
                    TestClientHelper.isTestClientWithAllowedEmail(
                            userContext, configurationService);
            var code =
                    isTestClient
                            ? getOtpCodeForTestClient(codeRequest.getNotificationType())
                            : codeStorageService.getOtpCode(
                                    session.getEmailAddress(), codeRequest.getNotificationType());

            var errorResponse =
                    ValidationHelper.validateVerificationCode(
                            codeRequest.getNotificationType(),
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
                        errorResponse.get(),
                        session,
                        codeRequest.getNotificationType(),
                        input,
                        userContext);
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            processSuccessfulCodeRequest(
                    session, codeRequest.getNotificationType(), input, userContext);

            return generateEmptySuccessApiGatewayResponse();
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private ErrorResponse blockedCodeBehaviour(VerifyCodeRequest codeRequest) {
        return Map.ofEntries(
                        entry(VERIFY_EMAIL, ErrorResponse.ERROR_1033),
                        entry(VERIFY_PHONE_NUMBER, ErrorResponse.ERROR_1034),
                        entry(MFA_SMS, ErrorResponse.ERROR_1027))
                .get(codeRequest.getNotificationType());
    }

    private boolean isCodeBlockedForSession(Session session) {
        return codeStorageService.isBlockedForEmail(
                session.getEmailAddress(), CODE_BLOCKED_KEY_PREFIX);
    }

    private void blockCodeForSession(Session session) {
        codeStorageService.saveBlockedForEmail(
                session.getEmailAddress(),
                CODE_BLOCKED_KEY_PREFIX,
                configurationService.getBlockedEmailDuration());
        LOG.info("Email is blocked");
    }

    private void resetIncorrectMfaCodeAttemptsCount(Session session) {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(session.getEmailAddress());
        LOG.info("IncorrectMfaCodeAttemptsCount reset");
    }

    private void processSuccessfulCodeRequest(
            Session session,
            NotificationType notificationType,
            APIGatewayProxyRequestEvent input,
            UserContext userContext) {
        var metadataPairs =
                new AuditService.MetadataPair[] {
                    pair("notification-type", notificationType.name())
                };
        var clientSession = userContext.getClientSession();
        var clientId = userContext.getClient().get().getClientID();
        var levelOfConfidence =
                clientSession.getEffectiveVectorOfTrust().containsLevelOfConfidence()
                        ? clientSession.getEffectiveVectorOfTrust().getLevelOfConfidence()
                        : NONE;

        if (notificationType.equals(VERIFY_PHONE_NUMBER)) {
            LOG.info(
                    "MFA code has been successfully verified for MFA type: {}. RegistrationJourney: {}",
                    MFAMethodType.SMS.getValue(),
                    true);
            authenticationService.updatePhoneNumberAndAccountVerifiedStatus(
                    session.getEmailAddress(), true);

            var vectorOfTrust = VectorOfTrust.getDefaults();

            if (Objects.nonNull(userContext.getClientSession().getEffectiveVectorOfTrust())
                    && userContext
                            .getClientSession()
                            .getEffectiveVectorOfTrust()
                            .containsLevelOfConfidence()) {
                vectorOfTrust = userContext.getClientSession().getEffectiveVectorOfTrust();
            }

            clientSessionService.saveClientSession(
                    userContext.getClientSessionId(),
                    userContext.getClientSession().setEffectiveVectorOfTrust(vectorOfTrust));
            sessionService.save(
                    session.setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL)
                            .setVerifiedMfaMethodType(MFAMethodType.SMS));
            metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("notification-type", notificationType.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue())
                    };
            cloudwatchMetricsService.incrementAuthenticationSuccess(
                    session.isNewAccount(),
                    clientId,
                    userContext.getClientName(),
                    levelOfConfidence.getValue(),
                    clientService.isTestJourney(clientId, session.getEmailAddress()),
                    clientSession
                            .getEffectiveVectorOfTrust()
                            .getCredentialTrustLevel()
                            .equals(CredentialTrustLevel.LOW_LEVEL));
        } else if (notificationType.equals(MFA_SMS)) {
            LOG.info(
                    "MFA code has been successfully verified for MFA type: {}. RegistrationJourney: {}",
                    MFAMethodType.SMS.getValue(),
                    false);
            sessionService.save(session.setVerifiedMfaMethodType(MFAMethodType.SMS));
            metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("notification-type", notificationType.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue())
                    };
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
            NotificationType notificationType,
            APIGatewayProxyRequestEvent input,
            UserContext userContext) {
        var metadataPairs =
                new AuditService.MetadataPair[] {
                    pair("notification-type", notificationType.name())
                };
        if (notificationType.equals(VERIFY_PHONE_NUMBER) || notificationType.equals(MFA_SMS)) {
            metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair("notification-type", notificationType.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue())
                    };
        }
        AuditableEvent auditableEvent;
        if (List.of(ErrorResponse.ERROR_1027, ErrorResponse.ERROR_1033, ErrorResponse.ERROR_1034)
                .contains(errorResponse)) {
            if (!notificationType.equals(VERIFY_EMAIL)
                    && !errorResponse.equals(ErrorResponse.ERROR_1033)) {
                blockCodeForSession(session);
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

    private Optional<String> getOtpCodeForTestClient(NotificationType notificationType)
            throws ClientNotFoundException {
        LOG.info("Using TestClient with NotificationType {}", notificationType);
        switch (notificationType) {
            case VERIFY_EMAIL:
                return configurationService.getTestClientVerifyEmailOTP();
            case VERIFY_PHONE_NUMBER:
            case MFA_SMS:
            case RESET_PASSWORD_WITH_CODE:
                return configurationService.getTestClientVerifyPhoneNumberOTP();
            default:
                LOG.error(
                        "Invalid NotificationType: {} configured for TestClient", notificationType);
                throw new RuntimeException("Invalid NotificationType for use with TestClient");
        }
    }
}
