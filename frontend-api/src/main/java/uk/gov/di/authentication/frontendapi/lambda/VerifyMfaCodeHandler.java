package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.CodeRequest;
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
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
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
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder.getReauthFailureReasonFromCountTypes;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INVALID_NOTIFICATION_TYPE;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.PhoneNumberHelper.formatPhoneNumber;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.mfa.MFAMethodsService.getMfaMethodOrDefaultMfaMethod;

public class VerifyMfaCodeHandler extends BaseFrontendHandler<VerifyMfaCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyMfaCodeHandler.class);
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final MfaCodeProcessorFactory mfaCodeProcessorFactory;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final AuthenticationAttemptsService authenticationAttemptsService;
    private final MFAMethodsService mfaMethodsService;

    public VerifyMfaCodeHandler(
            ConfigurationService configurationService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            MfaCodeProcessorFactory mfaCodeProcessorFactory,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthenticationAttemptsService authenticationAttemptsService,
            AuthSessionService authSessionService,
            MFAMethodsService mfaMethodsService) {
        super(
                VerifyMfaCodeRequest.class,
                configurationService,
                clientService,
                authenticationService,
                authSessionService);
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.mfaCodeProcessorFactory = mfaCodeProcessorFactory;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.mfaMethodsService = mfaMethodsService;
    }

    public VerifyMfaCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    public VerifyMfaCodeHandler(ConfigurationService configurationService) {
        super(VerifyMfaCodeRequest.class, configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.mfaCodeProcessorFactory =
                new MfaCodeProcessorFactory(
                        configurationService,
                        codeStorageService,
                        new DynamoService(configurationService),
                        auditService,
                        new DynamoAccountModifiersService(configurationService),
                        this.mfaMethodsService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public VerifyMfaCodeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(VerifyMfaCodeRequest.class, configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.mfaCodeProcessorFactory =
                new MfaCodeProcessorFactory(
                        configurationService,
                        codeStorageService,
                        new DynamoService(configurationService),
                        auditService,
                        new DynamoAccountModifiersService(configurationService),
                        this.mfaMethodsService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
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

        AuthSessionItem authSession = userContext.getAuthSession();

        var journeyType = codeRequest.getJourneyType();
        Optional<UserProfile> userProfileMaybe = userContext.getUserProfile();
        UserProfile userProfile = userProfileMaybe.orElse(null);
        Optional<ClientRegistry> clientMaybe = userContext.getClient();
        if (clientMaybe.isEmpty()) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.CLIENT_NOT_FOUND);
        }
        ClientRegistry client = clientMaybe.get();

        Optional<String> maybeRpPairwiseId = getRpPairwiseId(userProfile, authSession);

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
            return generateApiGatewayProxyErrorResponse(400, INVALID_NOTIFICATION_TYPE);

        if (userProfileMissingForReauthenticationJourney(userProfile, journeyType))
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.EMAIL_HAS_NO_USER_PROFILE);

        if (checkErrorCountsForReauthAndEmitFailedAuditEventIfBlocked(
                journeyType, userProfile, auditContext, maybeRpPairwiseId, client))
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS);

        try {
            String subjectID = userProfileMaybe.map(UserProfile::getSubjectID).orElse(null);
            return verifyCode(
                    input,
                    codeRequest,
                    userContext,
                    subjectID,
                    maybeRpPairwiseId,
                    client,
                    userProfile);
        } catch (Exception e) {
            LOG.error("Unexpected exception thrown", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }

    private static boolean isInvalidCodeRequestType(
            VerifyMfaCodeRequest codeRequest, JourneyType journeyType) {
        CodeRequestType.SupportedCodeType supportedCodeType =
                CodeRequestType.SupportedCodeType.getFromMfaMethodType(
                        codeRequest.getMfaMethodType());
        if (!CodeRequestType.isValidCodeRequestType(supportedCodeType, journeyType)) {
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
        return userProfile == null && journeyType == REAUTHENTICATION;
    }

    private boolean checkErrorCountsForReauthAndEmitFailedAuditEventIfBlocked(
            JourneyType journeyType,
            UserProfile userProfile,
            AuditContext auditContext,
            Optional<String> maybeRpPairwiseId,
            ClientRegistry client) {
        if (configurationService.isAuthenticationAttemptsServiceEnabled()
                && REAUTHENTICATION.equals(journeyType)
                && userProfile != null) {
            var counts =
                    maybeRpPairwiseId.isEmpty()
                            ? authenticationAttemptsService.getCountsByJourney(
                                    userProfile.getSubjectID(), REAUTHENTICATION)
                            : authenticationAttemptsService
                                    .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                            userProfile.getSubjectID(),
                                            maybeRpPairwiseId.get(),
                                            REAUTHENTICATION);
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
            ClientRegistry client,
            UserProfile userProfile) {

        var authSession = userContext.getAuthSession();
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
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.INVALID_NOTIFICATION_TYPE);
        }

        if (JourneyType.PASSWORD_RESET_MFA.equals(codeRequest.getJourneyType())) {
            SessionHelper.updateSessionWithSubject(
                    userContext, authSessionService, authenticationService, configurationService);
        }

        Optional<MFAMethod> activeMfaMethod = Optional.empty();
        var retrieveMfaMethods = mfaMethodsService.getMfaMethods(authSession.getEmailAddress());
        if (retrieveMfaMethods.isFailure()) {
            LOG.error(
                    "Failed to receive the users MFA methods because {}. Ignoring for audit events, this does not affect the journey",
                    retrieveMfaMethods.getFailure());
        } else {
            List<MFAMethod> retrievedMfaMethods = retrieveMfaMethods.getSuccess();
            activeMfaMethod =
                    retrievedMfaMethods.stream()
                            .filter(
                                    mfaMethod ->
                                            Objects.equals(
                                                    MFAMethodType.valueOf(
                                                            mfaMethod.getMfaMethodType()),
                                                    codeRequest.getMfaMethodType()))
                            .filter(
                                    codeRequest.getMfaMethodType() == MFAMethodType.SMS
                                            ? mfaMethod ->
                                                    Objects.equals(
                                                            formatPhoneNumber(
                                                                    mfaMethod.getDestination()),
                                                            formatPhoneNumber(
                                                                    codeRequest
                                                                            .getProfileInformation()))
                                            : mfaMethod -> true)
                            .findFirst();
        }

        var errorResponseMaybe = mfaCodeProcessor.validateCode();
        if (errorResponseMaybe.isPresent()) {
            var errorResponse = errorResponseMaybe.get();
            if (errorResponse.equals(ErrorResponse.INVALID_AUTH_APP_SECRET)) {
                return generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.INVALID_AUTH_APP_SECRET);
            }

            if (errorResponse.equals(ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED)
                    || errorResponse.equals(
                            ErrorResponse.TOO_MANY_INVALID_AUTH_APP_CODES_ENTERED)) {
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
                        REAUTHENTICATION,
                        CountType.ENTER_MFA_CODE);
            }

            auditFailure(codeRequest, errorResponse, authSession, auditContext, activeMfaMethod);
        } else {
            auditSuccess(codeRequest, authSession, auditContext, activeMfaMethod);
            processSuccessfulCodeSession(
                    userContext.getAuthSession(),
                    input,
                    subjectId,
                    codeRequest,
                    mfaCodeProcessor,
                    maybeRpPairwiseId,
                    userProfile);
        }

        authSessionService.updateSession(authSession);

        if (checkErrorCountsForReauthAndEmitFailedAuditEventIfBlocked(
                codeRequest.getJourneyType(),
                userContext.getUserProfile().orElse(null),
                auditContext,
                maybeRpPairwiseId,
                client)) {
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS);
        }

        return errorResponseMaybe
                .map(response -> generateApiGatewayProxyErrorResponse(400, response))
                .orElseGet(
                        () ->
                                handleSuccess(
                                        codeRequest, codeRequest.getJourneyType(), authSession));
    }

    private void auditSuccess(
            VerifyMfaCodeRequest codeRequest,
            AuthSessionItem authSession,
            AuditContext auditContext,
            Optional<MFAMethod> activeMfaMethod) {
        var metadataPairs =
                metadataPairsForEvent(
                        AUTH_CODE_VERIFIED,
                        authSession.getEmailAddress(),
                        codeRequest,
                        activeMfaMethod);
        auditService.submitAuditEvent(AUTH_CODE_VERIFIED, auditContext, metadataPairs);
    }

    private void auditFailure(
            VerifyMfaCodeRequest codeRequest,
            ErrorResponse errorResponse,
            AuthSessionItem authSession,
            AuditContext auditContext,
            Optional<MFAMethod> activeMfaMethod) {
        var auditableEvent = errorResponseAsFrontendAuditableEvent(errorResponse);
        var metadataPairs =
                metadataPairsForEvent(
                        auditableEvent,
                        authSession.getEmailAddress(),
                        codeRequest,
                        activeMfaMethod);
        auditService.submitAuditEvent(auditableEvent, auditContext, metadataPairs);
    }

    private APIGatewayProxyResponseEvent handleSuccess(
            VerifyMfaCodeRequest codeRequest,
            JourneyType journeyType,
            AuthSessionItem authSession) {

        var retrieveMfaMethods = mfaMethodsService.getMfaMethods(authSession.getEmailAddress());
        MFAMethodType mfaMethodType = null;
        PriorityIdentifier priorityIdentifier = null;
        if (retrieveMfaMethods.isFailure()) {
            LOG.error(
                    "Failed to retrieve MFA methods for user because {}",
                    retrieveMfaMethods.getFailure());
        } else {
            List<MFAMethod> retrievedMfaMethods = retrieveMfaMethods.getSuccess();
            if (codeRequest.getMfaMethodType().equals(MFAMethodType.AUTH_APP)) {
                mfaMethodType = MFAMethodType.AUTH_APP;
                priorityIdentifier =
                        getMfaMethodOrDefaultMfaMethod(
                                        retrievedMfaMethods, null, MFAMethodType.AUTH_APP)
                                .map(method -> PriorityIdentifier.valueOf(method.getPriority()))
                                .orElse(PriorityIdentifier.DEFAULT);
            } else if (codeRequest.getMfaMethodType().equals(MFAMethodType.SMS)) {
                mfaMethodType = MFAMethodType.SMS;
                priorityIdentifier = PriorityIdentifier.DEFAULT;
            }
        }

        var levelOfConfidence =
                Optional.ofNullable(authSession.getRequestedLevelOfConfidence()).orElse(NONE);

        LOG.info(
                "MFA code has been successfully verified for MFA type: {}. JourneyType: {}",
                codeRequest.getMfaMethodType().getValue(),
                journeyType);

        authSessionService.updateSession(
                authSession
                        .withVerifiedMfaMethodType(codeRequest.getMfaMethodType())
                        .withAchievedCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL));

        var clientId = authSession.getClientId();

        cloudwatchMetricsService.incrementAuthenticationSuccessWithMfa(
                authSession.getIsNewAccount(),
                clientId,
                authSession.getClientName(),
                levelOfConfidence.getValue(),
                clientService.isTestJourney(clientId, authSession.getEmailAddress()),
                journeyType,
                mfaMethodType,
                priorityIdentifier);

        return ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse();
    }

    private void processSuccessfulCodeSession(
            AuthSessionItem authSession,
            APIGatewayProxyRequestEvent input,
            String subjectId,
            VerifyMfaCodeRequest codeRequest,
            MfaCodeProcessor mfaCodeProcessor,
            Optional<String> maybeRpPairwiseId,
            UserProfile userProfile) {

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
                extractPersistentIdFromHeaders(input.getHeaders()),
                userProfile);

        if (JourneyType.ACCOUNT_RECOVERY.equals(codeRequest.getJourneyType())) {
            authSessionService.updateSession(
                    authSession.withResetMfaState(AuthSessionItem.ResetMfaState.SUCCEEDED));
        }
    }

    private FrontendAuditableEvent errorResponseAsFrontendAuditableEvent(
            ErrorResponse errorResponse) {

        Map<ErrorResponse, FrontendAuditableEvent> map =
                Map.ofEntries(
                        entry(
                                ErrorResponse.TOO_MANY_INVALID_AUTH_APP_CODES_ENTERED,
                                AUTH_CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.INVALID_AUTH_APP_CODE_ENTERED, AUTH_INVALID_CODE_SENT),
                        entry(
                                ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED,
                                AUTH_CODE_MAX_RETRIES_REACHED),
                        entry(ErrorResponse.INVALID_PHONE_CODE_ENTERED, AUTH_INVALID_CODE_SENT));

        return map.getOrDefault(errorResponse, FrontendAuditableEvent.AUTH_INVALID_CODE_SENT);
    }

    private void clearReauthErrorCountsForSuccessfullyAuthenticatedUser(String uniqueIdentifier) {
        Arrays.stream(CountType.values())
                .forEach(
                        countType ->
                                authenticationAttemptsService.deleteCount(
                                        uniqueIdentifier, REAUTHENTICATION, countType));
    }

    void preserveReauthCountsForAuditIfJourneyIsReauth(
            JourneyType journeyType,
            String subjectId,
            AuthSessionItem authSession,
            Optional<String> maybeRpPairwiseId) {
        if (journeyType == REAUTHENTICATION
                && configurationService.supportReauthSignoutEnabled()
                && configurationService.isAuthenticationAttemptsServiceEnabled()) {
            var counts =
                    maybeRpPairwiseId.isPresent()
                            ? authenticationAttemptsService
                                    .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                            subjectId, maybeRpPairwiseId.get(), REAUTHENTICATION)
                            : authenticationAttemptsService.getCountsByJourney(
                                    subjectId, REAUTHENTICATION);
            var updatedAuthSession = authSession.withPreservedReauthCountsForAuditMap(counts);
            authSessionService.updateSession(updatedAuthSession);
        }
    }

    private static boolean isInvalidReauthAuthAppAttempt(
            ErrorResponse errorResponse, VerifyMfaCodeRequest codeRequest) {
        return errorResponse == ErrorResponse.INVALID_AUTH_APP_CODE_ENTERED
                && codeRequest.getJourneyType() == REAUTHENTICATION;
    }

    private void blockCodeForSessionAndResetCountIfBlockDoesNotExist(
            String emailAddress, MFAMethodType mfaMethodType, JourneyType journeyType) {

        var codeRequestType = CodeRequestType.getCodeRequestType(mfaMethodType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (codeStorageService.isBlockedForEmail(emailAddress, codeBlockedKeyPrefix)) {
            return;
        }

        // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
        var deprecatedCodeRequestType =
                CodeRequestType.getDeprecatedCodeRequestTypeString(mfaMethodType, journeyType);
        if (codeStorageService.isBlockedForEmail(
                emailAddress, CODE_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType)) {
            return;
        }

        boolean reducedLockout =
                List.of(CodeRequestType.MFA_REGISTRATION, CodeRequestType.MFA_ACCOUNT_RECOVERY)
                        .contains(CodeRequestType.getCodeRequestType(mfaMethodType, journeyType));
        long blockDuration =
                reducedLockout
                        ? configurationService.getReducedLockoutDuration()
                        : configurationService.getLockoutDuration();

        if (!configurationService.supportReauthSignoutEnabled()
                || journeyType != REAUTHENTICATION) {
            codeStorageService.saveBlockedForEmail(
                    emailAddress, codeBlockedKeyPrefix, blockDuration);
        }

        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
    }

    private AuditService.MetadataPair[] metadataPairsForEvent(
            FrontendAuditableEvent auditableEvent,
            String email,
            VerifyMfaCodeRequest codeRequest,
            Optional<MFAMethod> activeMfaMethod) {
        var methodType = codeRequest.getMfaMethodType();
        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        metadataPairs.add(pair("mfa-type", methodType.getValue()));
        metadataPairs.add(
                pair(
                        "account-recovery",
                        codeRequest.getJourneyType() == JourneyType.ACCOUNT_RECOVERY));
        metadataPairs.add(pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, codeRequest.getJourneyType()));

        switch (auditableEvent) {
            case AUTH_CODE_MAX_RETRIES_REACHED -> {
                metadataPairs.add(
                        pair(
                                AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT,
                                configurationService.getCodeMaxRetries()));

                getPriorityIdentifier(codeRequest, activeMfaMethod)
                        .ifPresent(
                                identifier ->
                                        metadataPairs.add(
                                                pair(
                                                        AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                        identifier.name().toLowerCase())));
            }
            case AUTH_INVALID_CODE_SENT, AUTH_CODE_VERIFIED -> {
                if (auditableEvent.equals(AUTH_INVALID_CODE_SENT)) {
                    var failureCount = codeStorageService.getIncorrectMfaCodeAttemptsCount(email);
                    metadataPairs.add(pair("loginFailureCount", failureCount));
                }

                metadataPairs.add(pair("MFACodeEntered", codeRequest.getCode()));

                getPriorityIdentifier(codeRequest, activeMfaMethod)
                        .ifPresent(
                                identifier ->
                                        metadataPairs.add(
                                                pair(
                                                        AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                        identifier.name().toLowerCase())));
            }
        }

        return metadataPairs.stream().toArray(AuditService.MetadataPair[]::new);
    }

    private Optional<PriorityIdentifier> getPriorityIdentifier(
            CodeRequest codeRequest, Optional<MFAMethod> activeMfaMethod) {
        /*
        Ideally, we would be provided the mfaMethodId and be able to find the priority using that, but unfortunately
        we don't have that information to hand.

        https://govukverify.atlassian.net/wiki/spaces/LO/pages/5379588160/How+frontend+uses+backend+MFA+lambdas
        tells us which journeys this lambda may be called from.

        - ACCOUNT_RECOVERY (aka MFA reset) and REGISTRATION journeys have no MFA methods, so the priority can be DEFAULT
        - For all other journeys, activeMfaMethod should correctly find the method in use, which can tell us the priority
        */

        if (List.of(JourneyType.ACCOUNT_RECOVERY, JourneyType.REGISTRATION)
                .contains(codeRequest.getJourneyType())) {
            return Optional.of(PriorityIdentifier.DEFAULT);
        } else if (activeMfaMethod.isPresent()) {
            return Optional.of(PriorityIdentifier.valueOf(activeMfaMethod.get().getPriority()));
        } else {
            return Optional.empty();
        }
    }

    private Optional<String> getRpPairwiseId(UserProfile userProfile, AuthSessionItem authSession) {
        try {
            return Optional.of(
                    ClientSubjectHelper.getSubject(userProfile, authSession, authenticationService)
                            .getValue());
        } catch (RuntimeException e) {
            LOG.warn(
                    "Failed to derive Internal Common Subject Identifier. Defaulting to UNKNOWN.",
                    e);
            return Optional.empty();
        }
    }
}
