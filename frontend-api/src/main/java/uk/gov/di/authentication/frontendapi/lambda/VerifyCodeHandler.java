package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.frontendapi.helpers.SessionHelper;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
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
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
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
import static uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder.getReauthFailureReasonFromCountTypes;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT;

public class VerifyCodeHandler extends BaseFrontendHandler<VerifyCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyCodeHandler.class);

    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final DynamoAccountModifiersService accountModifiersService;
    private final AuthenticationAttemptsService authenticationAttemptsService;
    private final MFAMethodsService mfaMethodsService;

    protected VerifyCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            DynamoAccountModifiersService accountModifiersService,
            AuthenticationAttemptsService authenticationAttemptsService,
            AuthSessionService authSessionService,
            MFAMethodsService mfaMethodsService) {
        super(
                VerifyCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.accountModifiersService = accountModifiersService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.mfaMethodsService = mfaMethodsService;
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
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
    }

    public VerifyCodeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(VerifyCodeRequest.class, configurationService, redis);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.accountModifiersService = new DynamoAccountModifiersService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
        this.mfaMethodsService = new MFAMethodsService(configurationService);
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
        try {
            LOG.info("Processing request");

            var session = userContext.getSession();
            var sessionId = userContext.getAuthSession().getSessionId();
            AuthSessionItem authSession = userContext.getAuthSession();

            var notificationType = codeRequest.notificationType();
            var journeyType = getJourneyType(codeRequest, notificationType);
            var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
            var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            authSession.getInternalCommonSubjectId(),
                            authSession.getEmailAddress(),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            extractPersistentIdFromHeaders(input.getHeaders()));
            var client =
                    userContext
                            .getClient()
                            .orElseThrow(
                                    () ->
                                            new ClientNotFoundException(
                                                    "Could not find client in user context"));

            Optional<UserProfile> userProfileMaybe = userContext.getUserProfile();
            UserProfile userProfile = userProfileMaybe.orElse(null);
            Optional<String> maybeRpPairwiseId = getRpPairwiseId(userProfile, client);

            String subjectId = userProfile != null ? userProfile.getSubjectID() : null;

            if (journeyType == JourneyType.REAUTHENTICATION
                    && (userProfile == null || subjectId == null)) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);
            }

            if (checkReauthErrorCountsAndEmitReauthFailedAuditEvent(
                    journeyType, subjectId, auditContext, maybeRpPairwiseId))
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1057);

            if (isCodeBlockedForSession(authSession, codeBlockedKeyPrefix)) {
                ErrorResponse errorResponse = blockedCodeBehaviour(codeRequest);
                return generateApiGatewayProxyErrorResponse(400, errorResponse);
            }

            var retrieveMfaMethods = mfaMethodsService.getMfaMethods(authSession.getEmailAddress());
            List<MFAMethod> retrievedMfaMethods = new ArrayList<>();
            if (retrieveMfaMethods.isFailure()) {
                var failure = retrieveMfaMethods.getFailure();
                if (failure == USER_DOES_NOT_HAVE_ACCOUNT) {
                    LOG.info(
                            "User does not have account associated with email address, using empty list of MFA methods");
                } else if (failure
                        == UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP) {
                    return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1078);
                } else {
                    String message =
                            String.format(
                                    "Unexpected error occurred while retrieving mfa methods: %s",
                                    failure);
                    LOG.error(message);
                    return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1064);
                }
            } else {
                retrievedMfaMethods = retrieveMfaMethods.getSuccess();
            }
            var maybeDefaultSmsMfaMethod =
                    retrievedMfaMethods.stream()
                            .filter(
                                    mfaMethod ->
                                            Objects.equals(
                                                            mfaMethod.getPriority(),
                                                            PriorityIdentifier.DEFAULT.toString())
                                                    && Objects.equals(
                                                            mfaMethod.getMfaMethodType(),
                                                            MFAMethodType.SMS.toString()))
                            .findFirst();
            var code =
                    getCode(notificationType, authSession, userContext, maybeDefaultSmsMfaMethod);

            var errorResponse =
                    ValidationHelper.validateVerificationCode(
                            notificationType,
                            journeyType,
                            code,
                            codeRequest.code(),
                            codeStorageService,
                            authSession.getEmailAddress(),
                            configurationService);

            if (errorResponse.stream().anyMatch(ErrorResponse.ERROR_1002::equals)) {
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }

            sessionService.storeOrUpdateSession(session, sessionId);

            if (errorResponse.isPresent()) {
                handleInvalidVerificationCode(
                        codeRequest,
                        journeyType,
                        notificationType,
                        subjectId,
                        errorResponse.get(),
                        authSession,
                        auditContext);

                if (userHasExceededAllowedAttemptsForReauthenticationJourney(
                        journeyType, subjectId, auditContext, maybeRpPairwiseId)) {
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1057);
                }
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }

            if (codeRequestType.equals(CodeRequestType.PW_RESET_MFA_SMS)) {
                SessionHelper.updateSessionWithSubject(
                        userContext,
                        sessionService,
                        authSessionService,
                        authenticationService,
                        configurationService);
            }

            processSuccessfulCodeRequest(
                    codeRequest,
                    userContext,
                    subjectId,
                    journeyType,
                    auditContext,
                    client,
                    maybeRpPairwiseId,
                    maybeDefaultSmsMfaMethod);

            return generateEmptySuccessApiGatewayResponse();
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private boolean userHasExceededAllowedAttemptsForReauthenticationJourney(
            JourneyType journeyType,
            String subjectId,
            AuditContext auditContext,
            Optional<String> maybeRpPairwiseId) {
        return journeyType == JourneyType.REAUTHENTICATION
                && checkReauthErrorCountsAndEmitReauthFailedAuditEvent(
                        journeyType, subjectId, auditContext, maybeRpPairwiseId);
    }

    private Optional<String> getCode(
            NotificationType notificationType,
            AuthSessionItem authSession,
            UserContext userContext,
            Optional<MFAMethod> maybeDefaultSmsMfaMethod)
            throws ClientNotFoundException {
        if (isTestClientWithAllowedEmail(userContext, configurationService))
            return getOtpCodeForTestClient(notificationType);

        String emailAddress = authSession.getEmailAddress();
        String identifier = emailAddress;
        if (notificationType.isForPhoneNumber()) {
            var defaultSmsMfaMethod = maybeDefaultSmsMfaMethod.orElseThrow();
            String formattedPhoneNumber =
                    PhoneNumberHelper.formatPhoneNumber(defaultSmsMfaMethod.getDestination());
            identifier = emailAddress.concat(formattedPhoneNumber);
        }
        return codeStorageService
                .getOtpCode(identifier, notificationType)
                .or( // Temporary fallback for old phone number key with just email
                        () ->
                                notificationType.isForPhoneNumber()
                                        ? codeStorageService.getOtpCode(
                                                emailAddress, notificationType)
                                        : Optional.empty());
    }

    private void handleInvalidVerificationCode(
            VerifyCodeRequest codeRequest,
            JourneyType journeyType,
            NotificationType notificationType,
            String subjectId,
            ErrorResponse errorResponse,
            AuthSessionItem authSession,
            AuditContext auditContext) {
        if (journeyType == JourneyType.REAUTHENTICATION && notificationType == MFA_SMS) {
            if (configurationService.isAuthenticationAttemptsServiceEnabled()) {
                authenticationAttemptsService.createOrIncrementCount(
                        subjectId,
                        NowHelper.nowPlus(
                                        configurationService.getReauthEnterSMSCodeCountTTL(),
                                        ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond(),
                        JourneyType.REAUTHENTICATION,
                        CountType.ENTER_SMS_CODE);
            }
        } else {
            processBlockedCodeSession(
                    errorResponse, authSession, codeRequest, journeyType, auditContext);
        }
    }

    private boolean checkReauthErrorCountsAndEmitReauthFailedAuditEvent(
            JourneyType journeyType,
            String subjectId,
            AuditContext auditContext,
            Optional<String> maybeRpPairwiseId) {
        if (journeyType == JourneyType.REAUTHENTICATION
                && configurationService.isAuthenticationAttemptsServiceEnabled()) {
            var countsByJourney =
                    maybeRpPairwiseId.isEmpty()
                            ? authenticationAttemptsService.getCountsByJourney(
                                    subjectId, JourneyType.REAUTHENTICATION)
                            : authenticationAttemptsService
                                    .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                            subjectId,
                                            maybeRpPairwiseId.get(),
                                            JourneyType.REAUTHENTICATION);

            var countTypesWhereBlocked =
                    ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                            countsByJourney, configurationService);

            if (!countTypesWhereBlocked.isEmpty()) {
                ReauthFailureReasons failureReason =
                        getReauthFailureReasonFromCountTypes(countTypesWhereBlocked);
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        auditContext,
                        ReauthMetadataBuilder.builder(
                                        maybeRpPairwiseId.orElse(AuditService.UNKNOWN))
                                .withAllIncorrectAttemptCounts(countsByJourney)
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
                        countTypesWhereBlocked);
                return true;
            }
        }

        return false;
    }

    private ErrorResponse blockedCodeBehaviour(VerifyCodeRequest codeRequest) {
        return Map.ofEntries(
                        entry(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, ErrorResponse.ERROR_1048),
                        entry(VERIFY_EMAIL, ErrorResponse.ERROR_1033),
                        entry(RESET_PASSWORD_WITH_CODE, ErrorResponse.ERROR_1039),
                        entry(MFA_SMS, ErrorResponse.ERROR_1027))
                .get(codeRequest.notificationType());
    }

    private boolean isCodeBlockedForSession(
            AuthSessionItem authSession, String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(
                authSession.getEmailAddress(), codeBlockedKeyPrefix);
    }

    private void blockCodeForSession(AuthSessionItem authSession, String codeBlockPrefix) {
        codeStorageService.saveBlockedForEmail(
                authSession.getEmailAddress(),
                codeBlockPrefix,
                configurationService.getLockoutDuration());
        LOG.info("Email is blocked");
    }

    private void resetIncorrectMfaCodeAttemptsCount(AuthSessionItem authSession) {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(authSession.getEmailAddress());
        LOG.info("IncorrectMfaCodeAttemptsCount reset");
    }

    private void processSuccessfulCodeRequest(
            VerifyCodeRequest codeRequest,
            UserContext userContext,
            String subjectId,
            JourneyType journeyType,
            AuditContext auditContext,
            ClientRegistry client,
            Optional<String> maybeRpPairwiseId,
            Optional<MFAMethod> maybeDefaultSmsMfaMethod) {
        var authSession = userContext.getAuthSession();
        var notificationType = codeRequest.notificationType();
        int loginFailureCount =
                codeStorageService.getIncorrectMfaCodeAttemptsCount(authSession.getEmailAddress());
        var clientId = client.getClientID();
        var levelOfConfidence =
                Optional.ofNullable(authSession.getRequestedLevelOfConfidence()).orElse(NONE);

        if (notificationType.equals(MFA_SMS)) {
            LOG.info(
                    "MFA code has been successfully verified for MFA type: {}. RegistrationJourney: {}",
                    MFAMethodType.SMS.getValue(),
                    false);
            authSessionService.updateSession(
                    authSession
                            .withVerifiedMfaMethodType(MFAMethodType.SMS)
                            .withAchievedCredentialStrength(MEDIUM_LEVEL));
            clearAccountRecoveryBlockIfPresent(authSession, auditContext);
            cloudwatchMetricsService.incrementAuthenticationSuccess(
                    authSession.getIsNewAccount(),
                    clientId,
                    userContext.getClientName(),
                    levelOfConfidence.getValue(),
                    clientService.isTestJourney(clientId, authSession.getEmailAddress()),
                    true);
        }

        if (configurationService.isAuthenticationAttemptsServiceEnabled() && subjectId != null) {
            preserveReauthCountsForAuditIfJourneyIsReauth(
                    journeyType, subjectId, authSession, maybeRpPairwiseId);
            clearReauthErrorCountsForSuccessfullyAuthenticatedUser(subjectId);
            maybeRpPairwiseId.ifPresentOrElse(
                    this::clearReauthErrorCountsForSuccessfullyAuthenticatedUser,
                    () -> LOG.warn("Unable to clear rp pairwise id reauth counts"));
        }

        String emailAddress = authSession.getEmailAddress();
        String identifier = emailAddress;
        if (notificationType.isForPhoneNumber()) {
            var defaultSmsMfaMethod = maybeDefaultSmsMfaMethod.orElseThrow();
            String formattedPhoneNumber =
                    PhoneNumberHelper.formatPhoneNumber(defaultSmsMfaMethod.getDestination());
            identifier = emailAddress.concat(formattedPhoneNumber);
        }
        codeStorageService.deleteOtpCode(identifier, notificationType);
        if (notificationType.isForPhoneNumber()) {
            // Temporary fallback for old phone number key with just email
            codeStorageService.deleteOtpCode(emailAddress, notificationType);
        }

        var metadataPairArray =
                metadataPairs(notificationType, journeyType, codeRequest, loginFailureCount, false);
        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED, auditContext, metadataPairArray);
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

    void clearReauthErrorCountsForSuccessfullyAuthenticatedUser(String identifier) {
        Arrays.stream(CountType.values())
                .forEach(
                        countType ->
                                authenticationAttemptsService.deleteCount(
                                        identifier, JourneyType.REAUTHENTICATION, countType));
    }

    private AuditService.MetadataPair[] metadataPairs(
            NotificationType notificationType,
            JourneyType journeyType,
            VerifyCodeRequest codeRequest,
            Integer loginFailureCount,
            boolean isBlockedRequest) {
        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        metadataPairs.add(pair("notification-type", notificationType.name()));
        metadataPairs.add(pair("account-recovery", journeyType == JourneyType.ACCOUNT_RECOVERY));
        metadataPairs.add(pair("journey-type", String.valueOf(journeyType)));
        if (notificationType == MFA_SMS) {
            metadataPairs.add(pair("mfa-type", MFAMethodType.SMS.getValue()));
            metadataPairs.add(pair("loginFailureCount", loginFailureCount));
            metadataPairs.add(pair("MFACodeEntered", codeRequest.code()));
        }
        if (notificationType == MFA_SMS && isBlockedRequest) {
            metadataPairs.add(pair("MaxSmsCount", configurationService.getCodeMaxRetries()));
        }
        return metadataPairs.toArray(AuditService.MetadataPair[]::new);
    }

    private void processBlockedCodeSession(
            ErrorResponse errorResponse,
            AuthSessionItem authSession,
            VerifyCodeRequest codeRequest,
            JourneyType journeyType,
            AuditContext auditContext) {
        var notificationType = codeRequest.notificationType();
        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        AuditableEvent auditableEvent;
        switch (errorResponse) {
            case ERROR_1027:
            case ERROR_1039:
            case ERROR_1048:
                if (!configurationService.supportReauthSignoutEnabled()
                        || journeyType != JourneyType.REAUTHENTICATION) {
                    blockCodeForSession(authSession, codeBlockedKeyPrefix);
                }
                resetIncorrectMfaCodeAttemptsCount(authSession);
                auditableEvent = FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED;
                break;
            case ERROR_1033:
                resetIncorrectMfaCodeAttemptsCount(authSession);
                auditableEvent = FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED;
                break;
            default:
                auditableEvent = FrontendAuditableEvent.AUTH_INVALID_CODE_SENT;
                break;
        }
        var loginFailureCount =
                codeStorageService.getIncorrectMfaCodeAttemptsCount(authSession.getEmailAddress());
        var metadataPairArray =
                metadataPairs(notificationType, journeyType, codeRequest, loginFailureCount, true);
        auditService.submitAuditEvent(auditableEvent, auditContext, metadataPairArray);
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
            AuthSessionItem authSession, AuditContext auditContext) {
        var accountRecoveryBlockPresent =
                accountModifiersService.isAccountRecoveryBlockPresent(
                        authSession.getInternalCommonSubjectId());
        if (accountRecoveryBlockPresent) {
            LOG.info("AccountRecovery block is present. Removing block");
            accountModifiersService.removeAccountRecoveryBlockIfPresent(
                    authSession.getInternalCommonSubjectId());
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED,
                    auditContext,
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

    private Optional<String> getRpPairwiseId(UserProfile userProfile, ClientRegistry client) {
        try {
            var rpPairwiseId =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            client,
                            authenticationService,
                            configurationService.getInternalSectorUri());
            return Optional.of(rpPairwiseId.getValue());
        } catch (RuntimeException e) {
            LOG.warn("Failed to derive Internal Common Subject Identifier. Defaulting to UNKNOWN.");
            return Optional.empty();
        }
    }
}
