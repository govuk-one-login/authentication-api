package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.frontendapi.helpers.SessionHelper;
import uk.gov.di.authentication.frontendapi.validation.MfaCodeProcessor;
import uk.gov.di.authentication.frontendapi.validation.MfaCodeProcessorFactory;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Map.entry;
import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder.getReauthFailureReasonFromCountTypes;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
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
    private final AuthenticationAttemptsService authenticationAttemptsService;

    public VerifyMfaCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            MfaCodeProcessorFactory mfaCodeProcessorFactory,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthenticationAttemptsService authenticationAttemptsService,
            AuthSessionService authSessionService) {
        super(
                VerifyMfaCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.mfaCodeProcessorFactory = mfaCodeProcessorFactory;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.authenticationAttemptsService = authenticationAttemptsService;
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
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public VerifyMfaCodeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(VerifyMfaCodeRequest.class, configurationService, redis);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.mfaCodeProcessorFactory =
                new MfaCodeProcessorFactory(
                        configurationService,
                        codeStorageService,
                        new DynamoService(configurationService),
                        auditService,
                        new DynamoAccountModifiersService(configurationService));
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequestWithoutClientSession(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            VerifyMfaCodeRequest codeRequest,
            UserContext userContext) {

        AuthSessionItem authSession = userContext.getAuthSession();

        var journeyType = codeRequest.getJourneyType();
        Optional<UserProfile> userProfileMaybe = userContext.getUserProfile();
        UserProfile userProfile = userProfileMaybe.orElse(null);
        Optional<ClientRegistry> clientMaybe = userContext.getClient();
        if (clientMaybe.isEmpty()) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
        ClientRegistry client = clientMaybe.get();

        Optional<String> maybeRpPairwiseId = getRpPairwiseId(userProfile, client);

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        authSession.getInternalCommonSubjectId(),
                        authSession.getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        extractPersistentIdFromHeaders(input.getHeaders()));

        LOG.info("Invoking verify MFA code handler");

        if (isInvalidCodeRequestType(codeRequest, journeyType))
            return generateApiGatewayProxyErrorResponse(400, ERROR_1002);

        if (userProfileMissingForReauthenticationJourney(userProfile, journeyType))
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);

        if (checkErrorCountsForReauthAndEmitFailedAuditEventIfBlocked(
                journeyType, userProfile, auditContext, maybeRpPairwiseId, client))
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1057);

        try {
            String subjectID = userProfileMaybe.map(UserProfile::getSubjectID).orElse(null);
            return verifyCode(
                    input, codeRequest, userContext, subjectID, maybeRpPairwiseId, client);
        } catch (Exception e) {
            LOG.error("Unexpected exception thrown");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private static boolean isInvalidCodeRequestType(
            VerifyMfaCodeRequest codeRequest, JourneyType journeyType) {
        if (!CodeRequestType.isValidCodeRequestType(codeRequest.getMfaMethodType(), journeyType)) {
            LOG.warn(
                    "Invalid MFA Type '{}' for journey '{}'",
                    codeRequest.getMfaMethodType(),
                    journeyType);
            return true;
        }
        return false;
    }

    private static boolean userProfileMissingForReauthenticationJourney(
            UserProfile userProfile, JourneyType journeyType) {
        return userProfile == null && journeyType == JourneyType.REAUTHENTICATION;
    }

    private boolean checkErrorCountsForReauthAndEmitFailedAuditEventIfBlocked(
            JourneyType journeyType,
            UserProfile userProfile,
            AuditContext auditContext,
            Optional<String> maybeRpPairwiseId,
            ClientRegistry client) {
        if (configurationService.isAuthenticationAttemptsServiceEnabled()
                && JourneyType.REAUTHENTICATION.equals(journeyType)
                && userProfile != null) {
            var counts =
                    maybeRpPairwiseId.isEmpty()
                            ? authenticationAttemptsService.getCountsByJourney(
                                    userProfile.getSubjectID(), JourneyType.REAUTHENTICATION)
                            : authenticationAttemptsService
                                    .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                            userProfile.getSubjectID(),
                                            maybeRpPairwiseId.get(),
                                            JourneyType.REAUTHENTICATION);
            var countTypesWhereLimitExceeded =
                    ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                            counts, configurationService);

            if (!countTypesWhereLimitExceeded.isEmpty() && client != null) {
                ReauthFailureReasons failureReason =
                        getReauthFailureReasonFromCountTypes(countTypesWhereLimitExceeded);
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        auditContext,
                        ReauthMetadataBuilder.builder(
                                        maybeRpPairwiseId.orElse(AuditService.UNKNOWN))
                                .withAllIncorrectAttemptCounts(counts)
                                .withFailureReason(failureReason)
                                .build());
                cloudwatchMetricsService.incrementCounter(
                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                FAILURE_REASON.getValue(),
                                failureReason == null ? "unknown" : failureReason.getValue()));

                LOG.info(
                        "Re-authentication locked due to {} counts exceeded.",
                        countTypesWhereLimitExceeded);
                return true;
            }
        }
        return false;
    }

    private APIGatewayProxyResponseEvent verifyCode(
            APIGatewayProxyRequestEvent input,
            VerifyMfaCodeRequest codeRequest,
            UserContext userContext,
            String subjectId,
            Optional<String> maybeRpPairwiseId,
            ClientRegistry client) {

        var session = userContext.getSession();
        var authSession = userContext.getAuthSession();
        var sessionId = authSession.getSessionId();
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        authSession.getInternalCommonSubjectId(),
                        authSession.getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        extractPersistentIdFromHeaders(input.getHeaders()));

        var mfaCodeProcessor =
                mfaCodeProcessorFactory
                        .getMfaCodeProcessor(
                                codeRequest.getMfaMethodType(), codeRequest, userContext)
                        .orElse(null);

        if (Objects.isNull(mfaCodeProcessor)) {
            LOG.info("No MFA code validator found for this MFA method type");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
        }

        if (JourneyType.PASSWORD_RESET_MFA.equals(codeRequest.getJourneyType())) {
            SessionHelper.updateSessionWithSubject(
                    userContext,
                    sessionService,
                    authSessionService,
                    authenticationService,
                    configurationService);
        }

        var errorResponseMaybe = mfaCodeProcessor.validateCode();

        if (errorResponseMaybe.isPresent()) {
            var errorResponse = errorResponseMaybe.get();
            if (errorResponse.equals(ErrorResponse.ERROR_1041)) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1041);
            }

            if (errorResponse.equals(ErrorResponse.ERROR_1034)
                    || errorResponse.equals(ErrorResponse.ERROR_1042)) {
                blockCodeForSessionAndResetCountIfBlockDoesNotExist(
                        userContext.getAuthSession().getEmailAddress(),
                        codeRequest.getMfaMethodType(),
                        codeRequest.getJourneyType());
            }

            if (isInvalidReauthAuthAppAttempt(errorResponse, codeRequest)
                    && configurationService.isAuthenticationAttemptsServiceEnabled()
                    && subjectId != null) {
                authenticationAttemptsService.createOrIncrementCount(
                        subjectId,
                        NowHelper.nowPlus(
                                        configurationService.getReauthEnterAuthAppCodeCountTTL(),
                                        ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond(),
                        JourneyType.REAUTHENTICATION,
                        CountType.ENTER_AUTH_APP_CODE);
            }
            auditFailure(codeRequest, errorResponse, authSession, auditContext);
        } else {
            auditSuccess(codeRequest, authSession, auditContext);
            processSuccessfulCodeSession(
                    userContext.getAuthSession(),
                    input,
                    subjectId,
                    codeRequest,
                    mfaCodeProcessor,
                    maybeRpPairwiseId);
        }

        sessionService.storeOrUpdateSession(session, sessionId);

        if (checkErrorCountsForReauthAndEmitFailedAuditEventIfBlocked(
                codeRequest.getJourneyType(),
                userContext.getUserProfile().orElse(null),
                auditContext,
                maybeRpPairwiseId,
                client)) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1057);
        }

        return errorResponseMaybe
                .map(response -> generateApiGatewayProxyErrorResponse(400, response))
                .orElseGet(
                        () ->
                                handleSuccess(
                                        codeRequest,
                                        userContext,
                                        codeRequest.getJourneyType(),
                                        authSession,
                                        session));
    }

    private void auditSuccess(
            VerifyMfaCodeRequest codeRequest,
            AuthSessionItem authSession,
            AuditContext auditContext) {
        var metadataPairs =
                metadataPairsForEvent(
                        AUTH_CODE_VERIFIED, authSession.getEmailAddress(), codeRequest);
        auditService.submitAuditEvent(AUTH_CODE_VERIFIED, auditContext, metadataPairs);
    }

    private void auditFailure(
            VerifyMfaCodeRequest codeRequest,
            ErrorResponse errorResponse,
            AuthSessionItem authSession,
            AuditContext auditContext) {
        var auditableEvent = errorResponseAsFrontendAuditableEvent(errorResponse);
        var metadataPairs =
                metadataPairsForEvent(auditableEvent, authSession.getEmailAddress(), codeRequest);
        auditService.submitAuditEvent(auditableEvent, auditContext, metadataPairs);
    }

    private APIGatewayProxyResponseEvent handleSuccess(
            VerifyMfaCodeRequest codeRequest,
            UserContext userContext,
            JourneyType journeyType,
            AuthSessionItem authSession,
            Session session) {
        var clientSession = userContext.getClientSession();
        var levelOfConfidence =
                clientSession.getEffectiveVectorOfTrust().containsLevelOfConfidence()
                        ? clientSession.getEffectiveVectorOfTrust().getLevelOfConfidence()
                        : NONE;

        LOG.info(
                "MFA code has been successfully verified for MFA type: {}. JourneyType: {}",
                codeRequest.getMfaMethodType().getValue(),
                journeyType);

        sessionService.storeOrUpdateSession(
                session.setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL),
                userContext.getAuthSession().getSessionId());

        authSessionService.updateSession(
                authSession
                        .withVerifiedMfaMethodType(codeRequest.getMfaMethodType())
                        .withCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL)
                        .withAchievedCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL));

        var clientId = userContext.getClientId();

        cloudwatchMetricsService.incrementAuthenticationSuccess(
                authSession.getIsNewAccount(),
                clientId,
                userContext.getClientName(),
                levelOfConfidence.getValue(),
                clientService.isTestJourney(clientId, authSession.getEmailAddress()),
                true);

        return ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse();
    }

    private void processSuccessfulCodeSession(
            AuthSessionItem authSession,
            APIGatewayProxyRequestEvent input,
            String subjectId,
            VerifyMfaCodeRequest codeRequest,
            MfaCodeProcessor mfaCodeProcessor,
            Optional<String> maybeRpPairwiseId) {

        if (configurationService.isAuthenticationAttemptsServiceEnabled()
                && codeRequest.getMfaMethodType() == MFAMethodType.AUTH_APP
                && subjectId != null) {
            preserveReauthCountsForAuditIfJourneyIsReauth(
                    codeRequest.getJourneyType(), subjectId, authSession, maybeRpPairwiseId);
            clearReauthErrorCountsForSuccessfullyAuthenticatedUser(subjectId);
            maybeRpPairwiseId.ifPresentOrElse(
                    this::clearReauthErrorCountsForSuccessfullyAuthenticatedUser,
                    () -> LOG.warn("Unable to clear rp pairwise id reauth counts"));
        }
        mfaCodeProcessor.processSuccessfulCodeRequest(
                IpAddressHelper.extractIpAddress(input),
                extractPersistentIdFromHeaders(input.getHeaders()));

        if (JourneyType.ACCOUNT_RECOVERY.equals(codeRequest.getJourneyType())) {
            authSessionService.updateSession(
                    authSession.withResetMfaState(AuthSessionItem.ResetMfaState.SUCCEEDED));
        }
    }

    private FrontendAuditableEvent errorResponseAsFrontendAuditableEvent(
            ErrorResponse errorResponse) {

        Map<ErrorResponse, FrontendAuditableEvent> map =
                Map.ofEntries(
                        entry(ErrorResponse.ERROR_1042, AUTH_CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.ERROR_1043, AUTH_INVALID_CODE_SENT),
                        entry(ErrorResponse.ERROR_1034, AUTH_CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.ERROR_1037, AUTH_INVALID_CODE_SENT));

        return map.getOrDefault(errorResponse, FrontendAuditableEvent.AUTH_INVALID_CODE_SENT);
    }

    private void clearReauthErrorCountsForSuccessfullyAuthenticatedUser(String uniqueIdentifier) {
        Arrays.stream(CountType.values())
                .forEach(
                        countType ->
                                authenticationAttemptsService.deleteCount(
                                        uniqueIdentifier, JourneyType.REAUTHENTICATION, countType));
    }

    void preserveReauthCountsForAuditIfJourneyIsReauth(
            JourneyType journeyType,
            String subjectId,
            AuthSessionItem authSession,
            Optional<String> maybeRpPairwiseId) {
        if (journeyType == JourneyType.REAUTHENTICATION
                && configurationService.supportReauthSignoutEnabled()
                && configurationService.isAuthenticationAttemptsServiceEnabled()) {
            var counts =
                    maybeRpPairwiseId.isPresent()
                            ? authenticationAttemptsService
                                    .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                            subjectId,
                                            maybeRpPairwiseId.get(),
                                            JourneyType.REAUTHENTICATION)
                            : authenticationAttemptsService.getCountsByJourney(
                                    subjectId, JourneyType.REAUTHENTICATION);
            var updatedAuthSession = authSession.withPreservedReauthCountsForAuditMap(counts);
            authSessionService.updateSession(updatedAuthSession);
        }
    }

    private static boolean isInvalidReauthAuthAppAttempt(
            ErrorResponse errorResponse, VerifyMfaCodeRequest codeRequest) {
        return errorResponse == ErrorResponse.ERROR_1043
                && codeRequest.getJourneyType() == JourneyType.REAUTHENTICATION;
    }

    private void blockCodeForSessionAndResetCountIfBlockDoesNotExist(
            String emailAddress, MFAMethodType mfaMethodType, JourneyType journeyType) {

        var codeRequestType = CodeRequestType.getCodeRequestType(mfaMethodType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (codeStorageService.isBlockedForEmail(emailAddress, codeBlockedKeyPrefix)) {
            return;
        }
        boolean reducedLockout =
                List.of(CodeRequestType.SMS_REGISTRATION, CodeRequestType.SMS_ACCOUNT_RECOVERY)
                        .contains(CodeRequestType.getCodeRequestType(mfaMethodType, journeyType));
        long blockDuration =
                reducedLockout
                        ? configurationService.getReducedLockoutDuration()
                        : configurationService.getLockoutDuration();

        if (!configurationService.supportReauthSignoutEnabled()
                || journeyType != JourneyType.REAUTHENTICATION) {
            codeStorageService.saveBlockedForEmail(
                    emailAddress, codeBlockedKeyPrefix, blockDuration);
        }

        if (mfaMethodType == MFAMethodType.SMS) {
            codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
        } else {
            codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress, mfaMethodType);
        }
    }

    private AuditService.MetadataPair[] metadataPairsForEvent(
            FrontendAuditableEvent auditableEvent, String email, VerifyMfaCodeRequest codeRequest) {
        var methodType = codeRequest.getMfaMethodType();
        var basicMetadataPairs =
                List.of(
                        pair("mfa-type", methodType.getValue()),
                        pair(
                                "account-recovery",
                                codeRequest.getJourneyType() == JourneyType.ACCOUNT_RECOVERY),
                        pair("journey-type", codeRequest.getJourneyType()));
        var additionalPairs =
                switch (auditableEvent) {
                    case AUTH_CODE_MAX_RETRIES_REACHED -> List.of(
                            pair("attemptNoFailedAt", configurationService.getCodeMaxRetries()));
                    case AUTH_INVALID_CODE_SENT -> {
                        var failureCount =
                                methodType.equals(MFAMethodType.AUTH_APP)
                                        ? codeStorageService.getIncorrectMfaCodeAttemptsCount(
                                                email, MFAMethodType.AUTH_APP)
                                        : codeStorageService.getIncorrectMfaCodeAttemptsCount(
                                                email);
                        yield List.of(
                                pair("loginFailureCount", failureCount),
                                pair("MFACodeEntered", codeRequest.getCode()));
                    }
                    case AUTH_CODE_VERIFIED -> List.of(
                            pair("MFACodeEntered", codeRequest.getCode()));
                    default -> List.<AuditService.MetadataPair>of();
                };
        return Stream.concat(basicMetadataPairs.stream(), additionalPairs.stream())
                .toArray(AuditService.MetadataPair[]::new);
    }

    private Optional<String> getRpPairwiseId(UserProfile userProfile, ClientRegistry client) {
        try {
            return Optional.of(
                    ClientSubjectHelper.getSubject(
                                    userProfile,
                                    client,
                                    authenticationService,
                                    configurationService.getInternalSectorUri())
                            .getValue());
        } catch (RuntimeException e) {
            LOG.warn("Failed to derive Internal Common Subject Identifier. Defaulting to UNKNOWN.");
            return Optional.empty();
        }
    }
}
