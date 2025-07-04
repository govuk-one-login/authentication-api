package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.exceptions.AccountLockedException;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_ACCOUNT_IDENTIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED;
import static uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder.getReauthFailureReasonFromCountTypes;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1056;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class CheckReAuthUserHandler extends BaseFrontendHandler<CheckReauthUserRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckReAuthUserHandler.class);

    private final AuditService auditService;
    private final AuthenticationAttemptsService authenticationAttemptsService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            AuthenticationAttemptsService authenticationAttemptsService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthSessionService authSessionService) {
        super(
                CheckReauthUserRequest.class,
                configurationService,
                clientService,
                authenticationService,
                authSessionService);
        this.auditService = auditService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public CheckReAuthUserHandler(ConfigurationService configurationService) {
        super(CheckReauthUserRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    public CheckReAuthUserHandler() {
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
            CheckReauthUserRequest request,
            UserContext userContext) {

        var emailUserIsSignedInWith = userContext.getAuthSession().getEmailAddress();

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        AuditService.UNKNOWN,
                        emailUserIsSignedInWith,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var pairwiseIdMetadataPair = pair("rpPairwiseId", request.rpPairwiseId());

        Optional<UserProfile> maybeUserProfileOfUserSuppliedEmail =
                authenticationService.getUserProfileByEmailMaybe(request.email());

        try {
            return maybeUserProfileOfUserSuppliedEmail
                    .flatMap(
                            userProfile -> {
                                var updatedAuditContext =
                                        auditContext.withUserId(userProfile.getSubjectID());

                                throwLockedExceptionAndEmitAuditEventIfExistentUserIsLocked(
                                        userProfile, updatedAuditContext, request.rpPairwiseId());

                                return verifyReAuthentication(
                                        userProfile,
                                        userContext,
                                        request.rpPairwiseId(),
                                        updatedAuditContext,
                                        pairwiseIdMetadataPair);
                            })
                    .map(rpPairwiseId -> generateSuccessResponse())
                    .orElseGet(
                            () ->
                                    generateErrorResponse(
                                            emailUserIsSignedInWith,
                                            request.rpPairwiseId(),
                                            auditContext,
                                            pairwiseIdMetadataPair,
                                            request.email(),
                                            maybeUserProfileOfUserSuppliedEmail));
        } catch (AccountLockedException e) {
            LOG.error("Account is unable to reauth due to too many failed attempts.");
            return generateApiGatewayProxyErrorResponse(400, e.getErrorResponse());
        }
    }

    private Optional<String> verifyReAuthentication(
            UserProfile userProfile,
            UserContext userContext,
            String rpPairwiseId,
            AuditContext auditContext,
            AuditService.MetadataPair pairwiseIdMetadataPair) {
        var calculatedPairwiseId =
                ClientSubjectHelper.getSubject(
                                userProfile, userContext.getAuthSession(), authenticationService)
                        .getValue();

        if (calculatedPairwiseId != null && calculatedPairwiseId.equals(rpPairwiseId)) {
            // note here that this retrieval is duplicated a lot here. Currently duplicating so that
            // we don't hit merge conflicts with
            // other PRs that are forced to populate these values in audit events in different ways,
            // but
            // once these are done, we should make this consistent and just get these counts once.
            var incorrectEmailCount =
                    authenticationAttemptsService.getCount(
                            userProfile.getSubjectID(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_EMAIL);

            auditService.submitAuditEvent(
                    AUTH_REAUTH_ACCOUNT_IDENTIFIED,
                    auditContext,
                    pairwiseIdMetadataPair,
                    pair("incorrect_email_attempt_count", incorrectEmailCount));
            return Optional.of(rpPairwiseId);
        } else {
            LOG.warn("Could not calculate rp pairwise ID");
        }

        LOG.warn("User re-authentication verification failed");
        return Optional.empty();
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse() {
        LOG.info("Successfully processed CheckReAuthUser request");
        return generateApiGatewayProxyResponse(200, "");
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            String emailUserIsSignedInWith,
            String rpPairwiseId,
            AuditContext auditContext,
            AuditService.MetadataPair pairwiseIdMetadataPair,
            String userSuppliedEmail,
            Optional<UserProfile> userProfileOfSuppliedEmail) {

        String uniqueUserIdentifier;
        Optional<String> additionalIdentifier = Optional.empty();
        if (emailUserIsSignedInWith != null) {
            var userProfile = authenticationService.getUserProfileByEmail(emailUserIsSignedInWith);
            uniqueUserIdentifier = userProfile.getSubjectID();
            additionalIdentifier = Optional.of(rpPairwiseId);
        } else {
            uniqueUserIdentifier = rpPairwiseId;
        }

        authenticationAttemptsService.createOrIncrementCount(
                uniqueUserIdentifier,
                NowHelper.nowPlus(
                                configurationService.getReauthEnterEmailCountTTL(),
                                ChronoUnit.SECONDS)
                        .toInstant()
                        .getEpochSecond(),
                JourneyType.REAUTHENTICATION,
                CountType.ENTER_EMAIL);

        var updatedCount =
                authenticationAttemptsService.getCount(
                                uniqueUserIdentifier,
                                JourneyType.REAUTHENTICATION,
                                CountType.ENTER_EMAIL)
                        + additionalIdentifier
                                .map(
                                        identifier ->
                                                authenticationAttemptsService.getCount(
                                                        identifier,
                                                        JourneyType.REAUTHENTICATION,
                                                        CountType.ENTER_EMAIL))
                                .orElse(0);

        var pairBuilder =
                ReauthMetadataBuilder.builder(rpPairwiseId)
                        .withIncorrectEmailCount(updatedCount)
                        .withRestrictedUserSuppliedEmailPair(userSuppliedEmail);

        userProfileOfSuppliedEmail.ifPresent(
                userProfile ->
                        pairBuilder.withRestrictedUserIdForUserSuppliedEmailPair(
                                userProfile.getSubjectID()));

        auditService.submitAuditEvent(
                AUTH_REAUTH_INCORRECT_EMAIL_ENTERED, auditContext, pairBuilder.build());

        if (hasEnteredIncorrectEmailTooManyTimes(updatedCount)) {
            var incorrectCounts =
                    additionalIdentifier.isPresent()
                            ? authenticationAttemptsService
                                    .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                            uniqueUserIdentifier,
                                            additionalIdentifier.get(),
                                            JourneyType.REAUTHENTICATION)
                            : authenticationAttemptsService.getCountsByJourney(
                                    uniqueUserIdentifier, JourneyType.REAUTHENTICATION);

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                    auditContext,
                    ReauthMetadataBuilder.builder(rpPairwiseId)
                            .withAllIncorrectAttemptCounts(incorrectCounts)
                            .withFailureReason(ReauthFailureReasons.INCORRECT_EMAIL)
                            .build());
            cloudwatchMetricsService.incrementCounter(
                    CloudwatchMetrics.REAUTH_FAILED.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            FAILURE_REASON.getValue(),
                            ReauthFailureReasons.INCORRECT_EMAIL.getValue()));

            auditService.submitAuditEvent(
                    AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED,
                    auditContext,
                    pair(
                            AUDIT_EVENT_EXTENSIONS_ATTEMPT_NO_FAILED_AT,
                            configurationService.getMaxEmailReAuthRetries()),
                    pairwiseIdMetadataPair);
            throw new AccountLockedException(
                    "Re-authentication is locked due to too many failed attempts.",
                    ErrorResponse.ERROR_1057);
        }

        return generateApiGatewayProxyErrorResponse(404, ERROR_1056);
    }

    private boolean hasEnteredIncorrectEmailTooManyTimes(int count) {
        var maxRetries = configurationService.getMaxEmailReAuthRetries();

        return count >= maxRetries;
    }

    private void throwLockedExceptionAndEmitAuditEventIfExistentUserIsLocked(
            UserProfile userProfile, AuditContext auditContext, String pairwiseId)
            throws AccountLockedException {
        var countTypesToCounts =
                authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        userProfile.getSubjectID(), pairwiseId, JourneyType.REAUTHENTICATION);

        var exceededCountTypes =
                ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                        countTypesToCounts, configurationService);

        if (!exceededCountTypes.isEmpty()) {
            LOG.info(
                    "Account is locked due to exceeded counts on count types {}",
                    exceededCountTypes);
            ReauthFailureReasons failureReason =
                    getReauthFailureReasonFromCountTypes(exceededCountTypes);
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                    auditContext,
                    ReauthMetadataBuilder.builder(pairwiseId)
                            .withAllIncorrectAttemptCounts(countTypesToCounts)
                            .withFailureReason(failureReason)
                            .build());
            cloudwatchMetricsService.incrementCounter(
                    CloudwatchMetrics.REAUTH_FAILED.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            FAILURE_REASON.getValue(),
                            failureReason == null ? "unknown" : failureReason.getValue()));

            throw new AccountLockedException(
                    "Account is locked due to too many failed attempts.", ErrorResponse.ERROR_1057);
        }
    }
}
