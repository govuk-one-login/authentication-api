package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.helpers.SessionHelper;
import uk.gov.di.authentication.frontendapi.validation.MfaCodeProcessor;
import uk.gov.di.authentication.frontendapi.validation.MfaCodeProcessorFactory;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class VerifyMfaCodeHandler extends BaseFrontendHandler<VerifyMfaCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyMfaCodeHandler.class);
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final MfaCodeProcessorFactory mfaCodeProcessorFactory;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public VerifyMfaCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            MfaCodeProcessorFactory mfaCodeProcessorFactory,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                VerifyMfaCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.mfaCodeProcessorFactory = mfaCodeProcessorFactory;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public VerifyMfaCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    public VerifyMfaCodeHandler(ConfigurationService configurationService) {
        super(VerifyMfaCodeRequest.class, configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.mfaCodeProcessorFactory =
                new MfaCodeProcessorFactory(
                        configurationService,
                        codeStorageService,
                        new DynamoService(configurationService),
                        auditService,
                        new DynamoAccountModifiersService(configurationService));
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
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
            VerifyMfaCodeRequest codeRequest,
            UserContext userContext) {

        if (!CodeRequestType.isValidCodeRequestType(
                codeRequest.getMfaMethodType(), codeRequest.getJourneyType())) {
            LOG.warn(
                    "Invalid MFA Type '{}' for journey '{}'",
                    codeRequest.getMfaMethodType(),
                    codeRequest.getJourneyType());
            return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
        }

        LOG.info("Invoking verify MFA code handler");
        try {
            var session = userContext.getSession();
            var mfaMethodType = codeRequest.getMfaMethodType();

            var mfaCodeProcessor =
                    mfaCodeProcessorFactory
                            .getMfaCodeProcessor(mfaMethodType, codeRequest, userContext)
                            .orElse(null);

            if (Objects.isNull(mfaCodeProcessor)) {
                LOG.info("No MFA code validator found for this MFA method type");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
            }

            var errorResponse = mfaCodeProcessor.validateCode();

            if (errorResponse.filter(ErrorResponse.ERROR_1041::equals).isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1041);
            }
            if (JourneyType.PASSWORD_RESET_MFA.equals(codeRequest.getJourneyType())) {
                SessionHelper.updateSessionWithSubject(
                        userContext,
                        authenticationService,
                        configurationService,
                        sessionService,
                        session);
            }
            processCodeSession(
                    errorResponse, session, input, userContext, codeRequest, mfaCodeProcessor);

            sessionService.save(session);

            return errorResponse
                    .map(response -> generateApiGatewayProxyErrorResponse(400, response))
                    .orElseGet(
                            () -> {
                                var clientSession = userContext.getClientSession();
                                var clientId = userContext.getClient().get().getClientID();
                                var levelOfConfidence =
                                        clientSession
                                                        .getEffectiveVectorOfTrust()
                                                        .containsLevelOfConfidence()
                                                ? clientSession
                                                        .getEffectiveVectorOfTrust()
                                                        .getLevelOfConfidence()
                                                : NONE;

                                LOG.info(
                                        "MFA code has been successfully verified for MFA type: {}. JourneyType: {}",
                                        codeRequest.getMfaMethodType().getValue(),
                                        codeRequest.getJourneyType().getValue());
                                sessionService.save(
                                        session.setCurrentCredentialStrength(
                                                        CredentialTrustLevel.MEDIUM_LEVEL)
                                                .setVerifiedMfaMethodType(
                                                        codeRequest.getMfaMethodType()));
                                cloudwatchMetricsService.incrementAuthenticationSuccess(
                                        session.isNewAccount(),
                                        clientId,
                                        userContext.getClientName(),
                                        levelOfConfidence.getValue(),
                                        clientService.isTestJourney(
                                                clientId, session.getEmailAddress()),
                                        true);
                                return ApiGatewayResponseHelper
                                        .generateEmptySuccessApiGatewayResponse();
                            });

        } catch (Exception e) {
            LOG.error("Unexpected exception thrown");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private FrontendAuditableEvent errorResponseAsFrontendAuditableEvent(
            ErrorResponse errorResponse) {

        Map<ErrorResponse, FrontendAuditableEvent> map =
                Map.ofEntries(
                        entry(ErrorResponse.ERROR_1042, CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.ERROR_1043, INVALID_CODE_SENT),
                        entry(ErrorResponse.ERROR_1034, CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.ERROR_1037, INVALID_CODE_SENT));

        return map.getOrDefault(errorResponse, FrontendAuditableEvent.INVALID_CODE_SENT);
    }

    private void processCodeSession(
            Optional<ErrorResponse> errorResponse,
            Session session,
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            VerifyMfaCodeRequest codeRequest,
            MfaCodeProcessor mfaCodeProcessor) {
        var emailAddress = session.getEmailAddress();

        var auditableEvent =
                errorResponse
                        .map(this::errorResponseAsFrontendAuditableEvent)
                        .orElse(CODE_VERIFIED);

        submitAuditEvent(
                auditableEvent,
                session,
                userContext,
                input,
                codeRequest.getMfaMethodType(),
                codeRequest.getCode(),
                codeRequest.getJourneyType().equals(JourneyType.ACCOUNT_RECOVERY));

        if (errorResponse.isEmpty()) {
            mfaCodeProcessor.processSuccessfulCodeRequest(
                    IpAddressHelper.extractIpAddress(input),
                    extractPersistentIdFromHeaders(input.getHeaders()));
        }

        if (errorResponse
                .map(t -> List.of(ErrorResponse.ERROR_1034, ErrorResponse.ERROR_1042).contains(t))
                .orElse(false)) {
            blockCodeForSessionAndResetCountIfBlockDoesNotExist(
                    emailAddress, codeRequest.getMfaMethodType(), codeRequest.getJourneyType());
        }
    }

    private void blockCodeForSessionAndResetCountIfBlockDoesNotExist(
            String emailAddress, MFAMethodType mfaMethodType, JourneyType journeyType) {

        var codeRequestType = CodeRequestType.getCodeRequestType(mfaMethodType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (codeStorageService.isBlockedForEmail(emailAddress, codeBlockedKeyPrefix)) {
            return;
        }

        codeStorageService.saveBlockedForEmail(
                emailAddress, codeBlockedKeyPrefix, configurationService.getBlockedEmailDuration());

        if (mfaMethodType == MFAMethodType.SMS) {
            codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
        } else {
            codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType);
        }
    }

    private void submitAuditEvent(
            FrontendAuditableEvent auditableEvent,
            Session session,
            UserContext userContext,
            APIGatewayProxyRequestEvent input,
            MFAMethodType mfaMethodType,
            String code,
            boolean isAccountRecovery) {

        switch (auditableEvent) {
            case CODE_MAX_RETRIES_REACHED:
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
                        pair("mfa-type", mfaMethodType.getValue()),
                        pair("account-recovery", isAccountRecovery),
                        pair("attemptNoFailedAt", configurationService.getCodeMaxRetries()));
                break;
            case INVALID_CODE_SENT:
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
                        pair("mfa-type", mfaMethodType.getValue()),
                        pair("account-recovery", isAccountRecovery),
                        pair("loginFailureCount", session.getRetryCount()),
                        pair("MFACodeEntered", MFACode(input)));
                break;
            case CODE_VERIFIED:
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
                        pair("mfa-type", mfaMethodType.getValue()),
                        pair("account-recovery", isAccountRecovery),
                        pair("MFACodeEntered", code));
                break;
            default:
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
                        pair("mfa-type", mfaMethodType.getValue()),
                        pair("account-recovery", isAccountRecovery));
        }
    }

    private String MFACode(APIGatewayProxyRequestEvent input) {
        String body = input.getBody();
        int startIndex = body.indexOf("{\"mfaMethodType\"");
        int endIndex = body.lastIndexOf("}") + 1;
        String jsonPart = body.substring(startIndex, endIndex);

        String code = null;
        String[] parts = jsonPart.split(",");
        for (String part : parts) {
            if (part.contains("\"code\"")) {
                code = part.split(":")[1].replaceAll("\"", "").trim();
                break;
            }
        }
        return code;
    }
}
