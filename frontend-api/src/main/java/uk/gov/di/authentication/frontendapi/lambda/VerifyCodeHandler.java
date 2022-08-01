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
import uk.gov.di.authentication.shared.domain.RequestHeaders;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
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
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
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

            var code =
                    configurationService.isTestClientsEnabled()
                            ? getOtpCodeForTestClient(
                                    userContext, codeRequest.getNotificationType())
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
                        context,
                        userContext);
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            processSuccessfulCodeRequest(
                    session,
                    codeRequest.getNotificationType(),
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            RequestHeaders.CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive()),
                    input,
                    context,
                    userContext);

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

    private void blockCodeForSessionAndResetCount(Session session) {
        codeStorageService.saveBlockedForEmail(
                session.getEmailAddress(),
                CODE_BLOCKED_KEY_PREFIX,
                configurationService.getBlockedEmailDuration());
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(session.getEmailAddress());
    }

    private void processSuccessfulCodeRequest(
            Session session,
            NotificationType notificationType,
            String clientSessionId,
            APIGatewayProxyRequestEvent input,
            Context context,
            UserContext userContext) {
        if (notificationType.equals(VERIFY_PHONE_NUMBER)) {
            codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
            authenticationService.updatePhoneNumberVerifiedStatus(session.getEmailAddress(), true);

            var vectorOfTrust = VectorOfTrust.getDefaults();

            if (Objects.nonNull(userContext.getClientSession().getEffectiveVectorOfTrust())
                    && userContext
                            .getClientSession()
                            .getEffectiveVectorOfTrust()
                            .containsLevelOfConfidence()) {
                vectorOfTrust = userContext.getClientSession().getEffectiveVectorOfTrust();
            }

            clientSessionService.saveClientSession(
                    clientSessionId,
                    userContext.getClientSession().setEffectiveVectorOfTrust(vectorOfTrust));
            sessionService.save(
                    session.setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL));

            var clientName =
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN);

            cloudwatchMetricsService.incrementCounter(
                    "NewAccount",
                    Map.of(
                            "Environment",
                            configurationService.getEnvironment(),
                            "Client",
                            clientName));
        } else {
            codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
        }
        auditService.submitAuditEvent(
                FrontendAuditableEvent.CODE_VERIFIED,
                context.getAwsRequestId(),
                session.getSessionId(),
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                userContext
                        .getUserProfile()
                        .map(UserProfile::getSubjectID)
                        .orElse(AuditService.UNKNOWN),
                session.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                extractPersistentIdFromHeaders(input.getHeaders()),
                pair("notification-type", notificationType.name()));
    }

    private void processBlockedCodeSession(
            ErrorResponse errorResponse,
            Session session,
            NotificationType notificationType,
            APIGatewayProxyRequestEvent input,
            Context context,
            UserContext userContext) {
        AuditableEvent auditableEvent;
        if (List.of(ErrorResponse.ERROR_1027, ErrorResponse.ERROR_1033, ErrorResponse.ERROR_1034)
                .contains(errorResponse)) {
            blockCodeForSessionAndResetCount(session);
            auditableEvent = FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
        } else {
            auditableEvent = FrontendAuditableEvent.INVALID_CODE_SENT;
        }
        auditService.submitAuditEvent(
                auditableEvent,
                context.getAwsRequestId(),
                session.getSessionId(),
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                userContext
                        .getUserProfile()
                        .map(UserProfile::getSubjectID)
                        .orElse(AuditService.UNKNOWN),
                session.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                extractPersistentIdFromHeaders(input.getHeaders()),
                pair("notification-type", notificationType.name()));
    }

    private Optional<String> getOtpCodeForTestClient(
            UserContext userContext, NotificationType notificationType)
            throws ClientNotFoundException {
        LOG.warn("TestClients are ENABLED");
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
                                        "Using TestClient with NotificationType {}",
                                        notificationType);
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
                                                "Returning the generated OTP for NotificationType {}",
                                                notificationType);
                                        return generatedOTPCode;
                                }
                            } else {
                                return generatedOTPCode;
                            }
                        })
                .orElseThrow(() -> new ClientNotFoundException(userContext.getSession()));
    }
}
