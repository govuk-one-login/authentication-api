package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.conditions.TermsAndConditionsHelper;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_NO_ACCOUNT_WITH_EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.redactPhoneNumber;
import static uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder.getReauthFailureReasonFromCountTypes;
import static uk.gov.di.authentication.frontendapi.services.UserMigrationService.userHasBeenPartlyMigrated;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getUserMFADetail;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class LoginHandler extends BaseFrontendHandler<LoginRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final String CODE_BLOCKED_KEY_PREFIX =
            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET;
    private static final Logger LOG = LogManager.getLogger(LoginHandler.class);
    public static final String NUMBER_OF_ATTEMPTS_USER_ALLOWED_TO_LOGIN =
            "number_of_attempts_user_allowed_to_login";
    public static final String ATTEMPT_NO_FAILED_AT = "attemptNoFailedAt";
    public static final String INTERNAL_SUBJECT_ID = "internalSubjectId";
    public static final String INCORRECT_PASSWORD_COUNT = "incorrectPasswordCount";
    public static final String PASSWORD_RESET_TYPE = "passwordResetType";
    private final CodeStorageService codeStorageService;
    private final UserMigrationService userMigrationService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final CommonPasswordsService commonPasswordsService;
    private final AuthenticationAttemptsService authenticationAttemptsService;

    public LoginHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            AuthenticationService authenticationService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            CodeStorageService codeStorageService,
            UserMigrationService userMigrationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            CommonPasswordsService commonPasswordsService,
            AuthenticationAttemptsService authenticationAttemptsService,
            AuthSessionService authSessionService) {
        super(
                LoginRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService,
                true,
                authSessionService);
        this.codeStorageService = codeStorageService;
        this.userMigrationService = userMigrationService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.commonPasswordsService = commonPasswordsService;
        this.authenticationAttemptsService = authenticationAttemptsService;
    }

    public LoginHandler(ConfigurationService configurationService) {
        super(LoginRequest.class, configurationService, true);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.userMigrationService =
                new UserMigrationService(
                        new DynamoService(configurationService), configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public LoginHandler(ConfigurationService configurationService, RedisConnectionService redis) {
        super(LoginRequest.class, configurationService, true, redis);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.userMigrationService =
                new UserMigrationService(
                        new DynamoService(configurationService), configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public LoginHandler() {
        this(ConfigurationService.getInstance());
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
            LoginRequest request,
            UserContext userContext) {

        AuthSessionItem authSession = userContext.getAuthSession();

        AuditContext auditContext =
                auditContextFromUserContext(
                        userContext,
                        AuditService.UNKNOWN,
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var journeyType =
                request.getJourneyType() != null ? request.getJourneyType().getValue() : "missing";
        var isReauthJourney = journeyType.equalsIgnoreCase(JourneyType.REAUTHENTICATION.getValue());

        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());
        attachLogFieldToLogs(JOURNEY_TYPE, journeyType);

        Optional<UserProfile> userProfileMaybe =
                authenticationService.getUserProfileByEmailMaybe(request.getEmail());

        if (userProfileMaybe.isEmpty() || userContext.getUserCredentials().isEmpty()) {
            auditService.submitAuditEvent(AUTH_NO_ACCOUNT_WITH_EMAIL, auditContext);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
        }

        UserProfile userProfile = userProfileMaybe.get();
        var calculatedPairwiseId = calculatePairwiseId(userContext, userProfile);
        UserCredentials userCredentials = userContext.getUserCredentials().get();
        auditContext = auditContext.withPhoneNumber(userProfile.getPhoneNumber());

        var internalCommonSubjectId = getInternalCommonSubjectId(userProfile);
        auditContext = auditContext.withUserId(internalCommonSubjectId);

        if (isReauthJourneyWithFlagsEnabled(isReauthJourney)) {
            var reauthCounts =
                    authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            userProfile.getSubjectID(),
                            calculatedPairwiseId,
                            JourneyType.REAUTHENTICATION);
            var exceedingCounts =
                    ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                            reauthCounts, configurationService);
            if (!exceedingCounts.isEmpty()) {
                LOG.info("User has existing reauth block on counts {}", exceedingCounts);
                ReauthFailureReasons failureReason =
                        getReauthFailureReasonFromCountTypes(exceedingCounts);
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        auditContext,
                        ReauthMetadataBuilder.builder(calculatedPairwiseId)
                                .withAllIncorrectAttemptCounts(reauthCounts)
                                .withFailureReason(failureReason)
                                .build());
                cloudwatchMetricsService.incrementCounter(
                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                FAILURE_REASON.getValue(),
                                failureReason == null ? "unknown" : failureReason.getValue()));

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1057);
            }
        }

        int incorrectPasswordCount = 0;

        if (isReauthJourneyWithFlagsEnabled(isReauthJourney)) {
            incorrectPasswordCount =
                    authenticationAttemptsService.getCount(
                            userProfile.getSubjectID(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_PASSWORD);
        } else {
            incorrectPasswordCount =
                    retrieveIncorrectPasswordCount(request.getEmail(), isReauthJourney);
        }

        if (codeStorageService.isBlockedForEmail(userProfile.getEmail(), CODE_BLOCKED_KEY_PREFIX)) {
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                    auditContext,
                    pair(INTERNAL_SUBJECT_ID, userProfile.getSubjectID()),
                    pair(ATTEMPT_NO_FAILED_AT, configurationService.getMaxPasswordRetries()),
                    pair(NUMBER_OF_ATTEMPTS_USER_ALLOWED_TO_LOGIN, incorrectPasswordCount));

            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1028);
        }

        if (!credentialsAreValid(request, userProfile)) {
            return handleInvalidCredentials(
                    request,
                    incorrectPasswordCount,
                    auditContext,
                    userProfile,
                    isReauthJourney,
                    calculatedPairwiseId);
        }

        return handleValidCredentials(
                request,
                userContext,
                internalCommonSubjectId,
                userCredentials,
                userProfile,
                auditContext,
                authSession);
    }

    private String calculatePairwiseId(UserContext userContext, UserProfile userProfile) {
        var client = userContext.getClient().orElseThrow();
        return ClientSubjectHelper.getSubject(
                        userProfile,
                        client,
                        authenticationService,
                        configurationService.getInternalSectorUri())
                .getValue();
    }

    private boolean isReauthJourneyWithFlagsEnabled(boolean isReauthJourney) {
        return isReauthJourney
                && configurationService.supportReauthSignoutEnabled()
                && configurationService.isAuthenticationAttemptsServiceEnabled();
    }

    private APIGatewayProxyResponseEvent handleValidCredentials(
            LoginRequest request,
            UserContext userContext,
            String internalCommonSubjectIdentifier,
            UserCredentials userCredentials,
            UserProfile userProfile,
            AuditContext auditContext,
            AuthSessionItem authSessionItem) {

        authSessionService.updateSession(
                authSessionItem
                        .withAccountState(AuthSessionItem.AccountState.EXISTING)
                        .withInternalCommonSubjectId(internalCommonSubjectIdentifier));

        var userMfaDetail =
                getUserMFADetail(
                        userContext,
                        userCredentials,
                        userProfile.getPhoneNumber(),
                        userProfile.isPhoneNumberVerified(),
                        userProfile);

        boolean isPasswordChangeRequired = isPasswordResetRequired(request.getPassword());

        var pairs = new ArrayList<AuditService.MetadataPair>();

        pairs.add(pair(INTERNAL_SUBJECT_ID, userProfile.getSubjectID()));

        if (isPasswordChangeRequired) {
            pairs.add(pair(PASSWORD_RESET_TYPE, PasswordResetType.FORCED_WEAK_PASSWORD));
        }

        LOG.info(
                "User has successfully logged in with MFAType: {}. MFAVerified: {}",
                userMfaDetail.mfaMethodType().getValue(),
                userMfaDetail.mfaMethodVerified());

        auditService.submitAuditEvent(
                AUTH_LOG_IN_SUCCESS, auditContext, pairs.toArray(AuditService.MetadataPair[]::new));

        if (!userMfaDetail.isMfaRequired()) {
            cloudwatchMetricsService.incrementAuthenticationSuccess(
                    AuthSessionItem.AccountState.EXISTING,
                    userContext.getClientId(),
                    userContext.getClientName(),
                    "P0",
                    clientService.isTestJourney(userContext.getClientId(), userProfile.getEmail()),
                    false);
        }

        String redactedPhoneNumber =
                userProfile.isPhoneNumberVerified()
                        ? redactPhoneNumber(userProfile.getPhoneNumber())
                        : null;

        boolean termsAndConditionsAccepted = isTermsAndConditionsAccepted(userContext, userProfile);

        try {
            return generateApiGatewayProxyResponse(
                    200,
                    new LoginResponse(
                            redactedPhoneNumber,
                            userMfaDetail,
                            termsAndConditionsAccepted,
                            isPasswordChangeRequired));
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private APIGatewayProxyResponseEvent handleInvalidCredentials(
            LoginRequest request,
            int incorrectPasswordCount,
            AuditContext auditContext,
            UserProfile userProfile,
            boolean isReauthJourney,
            String calculatedPairwiseId) {
        var updatedIncorrectPasswordCount = incorrectPasswordCount + 1;

        incrementCountOfFailedAttemptsToProvidePassword(userProfile, isReauthJourney);

        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS,
                auditContext,
                pair(INTERNAL_SUBJECT_ID, userProfile.getSubjectID()),
                pair(INCORRECT_PASSWORD_COUNT, updatedIncorrectPasswordCount),
                pair(ATTEMPT_NO_FAILED_AT, configurationService.getMaxPasswordRetries()));

        if (updatedIncorrectPasswordCount >= configurationService.getMaxPasswordRetries()) {
            if (isReauthJourneyWithFlagsEnabled(isReauthJourney)) {
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        auditContext,
                        ReauthMetadataBuilder.builder(calculatedPairwiseId)
                                .withAllIncorrectAttemptCounts(
                                        authenticationAttemptsService
                                                .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                                        userProfile.getSubjectID(),
                                                        calculatedPairwiseId,
                                                        JourneyType.REAUTHENTICATION))
                                .withFailureReason(ReauthFailureReasons.INCORRECT_PASSWORD)
                                .build());
                cloudwatchMetricsService.incrementCounter(
                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                FAILURE_REASON.getValue(),
                                ReauthFailureReasons.INCORRECT_PASSWORD.getValue()));
            }

            if (isJourneyWhereBlockingApplies(isReauthJourney)) {
                blockUser(
                        userProfile.getSubjectID(),
                        request.getEmail(),
                        updatedIncorrectPasswordCount,
                        auditContext);
            }
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1028);
        }

        return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1008);
    }

    private boolean isJourneyWhereBlockingApplies(boolean isReauthJourney) {
        return !(isReauthJourney && configurationService.supportReauthSignoutEnabled());
    }

    private void incrementCountOfFailedAttemptsToProvidePassword(
            UserProfile userProfile, boolean isReauthJourney) {
        if (configurationService.supportReauthSignoutEnabled() && isReauthJourney) {
            if (configurationService.isAuthenticationAttemptsServiceEnabled()) {
                authenticationAttemptsService.createOrIncrementCount(
                        userProfile.getSubjectID(),
                        NowHelper.nowPlus(
                                        configurationService.getReauthEnterPasswordCountTTL(),
                                        ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond(),
                        JourneyType.REAUTHENTICATION,
                        CountType.ENTER_PASSWORD);
            } else {
                codeStorageService.increaseIncorrectPasswordCountReauthJourney(
                        userProfile.getEmail());
            }
        } else {
            codeStorageService.increaseIncorrectPasswordCount(userProfile.getEmail());
        }
    }

    private int retrieveIncorrectPasswordCount(String email, boolean isReauthJourney) {
        return isReauthJourney
                ? codeStorageService.getIncorrectPasswordCountReauthJourney(email)
                : codeStorageService.getIncorrectPasswordCount(email);
    }

    private String getInternalCommonSubjectId(UserProfile userProfile) {
        var internalCommonSubjectId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                        userProfile,
                        configurationService.getInternalSectorUri(),
                        authenticationService);
        return internalCommonSubjectId.getValue();
    }

    private boolean isTermsAndConditionsAccepted(UserContext userContext, UserProfile userProfile) {
        if (userProfile.getTermsAndConditions() == null) {
            return false;
        }
        var isSmokeTestClient =
                userContext.getClient().map(ClientRegistry::isSmokeTest).orElse(false);
        return TermsAndConditionsHelper.hasTermsAndConditionsBeenAccepted(
                userProfile.getTermsAndConditions(),
                configurationService.getTermsAndConditionsVersion(),
                isSmokeTestClient);
    }

    private void blockUser(
            String subjectID,
            String email,
            int updatedIncorrectPasswordCount,
            AuditContext auditContext) {
        LOG.info("User has now exceeded max password retries, setting block");

        codeStorageService.saveBlockedForEmail(
                email, CODE_BLOCKED_KEY_PREFIX, configurationService.getLockoutDuration());

        codeStorageService.deleteIncorrectPasswordCount(email);

        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                auditContext,
                pair(INTERNAL_SUBJECT_ID, subjectID),
                pair(ATTEMPT_NO_FAILED_AT, updatedIncorrectPasswordCount),
                pair(
                        NUMBER_OF_ATTEMPTS_USER_ALLOWED_TO_LOGIN,
                        configurationService.getMaxPasswordRetries()));
    }

    private boolean credentialsAreValid(LoginRequest request, UserProfile userProfile) {
        var userCredentials = authenticationService.getUserCredentialsFromEmail(request.getEmail());

        var userIsAMigratedUser =
                userHasBeenPartlyMigrated(userProfile.getLegacySubjectID(), userCredentials);

        if (userIsAMigratedUser) {
            LOG.info("Processing migrated user");
            return userMigrationService.processMigratedUser(userCredentials, request.getPassword());
        } else {
            return authenticationService.login(userCredentials, request.getPassword());
        }
    }

    private boolean isPasswordResetRequired(String password) {
        try {
            boolean passwordChangeRequest = commonPasswordsService.isCommonPassword(password);
            LOG.info("Password reset required: {}", passwordChangeRequest);
            return passwordChangeRequest;
        } catch (Exception e) {
            LOG.error("Unable to check if password was a common password");
            return false;
        }
    }
}
