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
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.temporal.ChronoUnit;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_ACCOUNT_IDENTIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1056;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class CheckReAuthUserHandler extends BaseFrontendHandler<CheckReauthUserRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckReAuthUserHandler.class);

    private final AuditService auditService;
    private final AuthenticationAttemptsService authenticationAttemptsService;

    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            AuthenticationAttemptsService authenticationAttemptsService) {
        super(
                CheckReauthUserRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.authenticationAttemptsService = authenticationAttemptsService;
    }

    public CheckReAuthUserHandler(ConfigurationService configurationService) {
        super(CheckReauthUserRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public CheckReAuthUserHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(CheckReauthUserRequest.class, configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
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

        var emailUserIsSignedInWith = userContext.getSession().getEmailAddress();

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

        AtomicReference<Map<CountType, Integer>> maybeExistingCounts = new AtomicReference<>();

        try {
            return maybeUserProfileOfUserSuppliedEmail
                    .flatMap(
                            userProfile -> {
                                var updatedAuditContext =
                                        auditContext.withUserId(userProfile.getSubjectID());

                                var countTypesToCounts =
                                        authenticationAttemptsService.getCountsByJourney(
                                                userProfile.getSubjectID(),
                                                JourneyType.REAUTHENTICATION);

                                maybeExistingCounts.set(countTypesToCounts);

                                var exceededCountTypes =
                                        ReauthAuthenticationAttemptsHelper
                                                .countTypesWhereUserIsBlockedForReauth(
                                                        countTypesToCounts, configurationService);

                                if (!exceededCountTypes.isEmpty()) {
                                    LOG.info(
                                            "Account is locked due to exceeded counts on count types {}",
                                            exceededCountTypes);
                                    auditService.submitAuditEvent(
                                            FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                                            updatedAuditContext,
                                            ReauthMetadataBuilder.builder(request.rpPairwiseId())
                                                    .withAllIncorrectAttemptCounts(
                                                            countTypesToCounts)
                                                    .withFailureReason(exceededCountTypes)
                                                    .build());

                                    throw new AccountLockedException(
                                            "Account is locked due to too many failed attempts.",
                                            ErrorResponse.ERROR_1057);
                                }

                                return verifyReAuthentication(
                                        userProfile,
                                        userContext,
                                        request.rpPairwiseId(),
                                        updatedAuditContext,
                                        pairwiseIdMetadataPair,
                                        countTypesToCounts);
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
                                            maybeUserProfileOfUserSuppliedEmail,
                                            Optional.ofNullable(maybeExistingCounts.get())));
        } catch (AccountLockedException e) {
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                    auditContext,
                    e.getErrorResponse() == ErrorResponse.ERROR_1045
                            ? pair(
                                    "number_of_attempts_user_allowed_to_login",
                                    configurationService.getMaxPasswordRetries())
                            : pair(
                                    "number_of_attempts_user_allowed_to_login",
                                    configurationService.getMaxEmailReAuthRetries()));

            LOG.error("Account is locked due to too many failed attempts.");
            return generateApiGatewayProxyErrorResponse(400, e.getErrorResponse());
        }
    }

    private Optional<String> verifyReAuthentication(
            UserProfile userProfile,
            UserContext userContext,
            String rpPairwiseId,
            AuditContext auditContext,
            AuditService.MetadataPair pairwiseIdMetadataPair,
            Map<CountType, Integer> existingCountTypes) {
        var client = userContext.getClient().orElseThrow();

        var calculatedPairwiseId =
                ClientSubjectHelper.getSubject(
                                userProfile,
                                client,
                                authenticationService,
                                configurationService.getInternalSectorUri())
                        .getValue();

        if (calculatedPairwiseId != null && calculatedPairwiseId.equals(rpPairwiseId)) {

            auditService.submitAuditEvent(
                    AUTH_REAUTH_ACCOUNT_IDENTIFIED,
                    auditContext,
                    pairwiseIdMetadataPair,
                    pair(
                            "incorrect_email_attempt_count",
                            existingCountTypes.getOrDefault(CountType.ENTER_EMAIL, 0)));
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
            Optional<UserProfile> userProfileOfSuppliedEmail,
            Optional<Map<CountType, Integer>> maybeExistingCounts) {

        String uniqueUserIdentifier;
        if (emailUserIsSignedInWith != null) {
            var userProfile = authenticationService.getUserProfileByEmail(emailUserIsSignedInWith);
            uniqueUserIdentifier = userProfile.getSubjectID();
        } else {
            uniqueUserIdentifier = rpPairwiseId;
        }

        var updatedCounts =
                incrementEmailCountAndRetrieveNewCounts(maybeExistingCounts, uniqueUserIdentifier);
        var updatedEnterEmailCount = updatedCounts.getOrDefault(CountType.ENTER_EMAIL, 0);

        var metadataBuilder =
                ReauthMetadataBuilder.builder(rpPairwiseId)
                        .withIncorrectEmailAttemptCount(updatedEnterEmailCount)
                        .withRestrictedUserSuppliedEmail(userSuppliedEmail);

        userProfileOfSuppliedEmail.ifPresent(
                userProfile ->
                        metadataBuilder.withRestrictedUserIdForUserSuppliedEmail(
                                userProfile.getSubjectID()));

        auditService.submitAuditEvent(
                AUTH_REAUTH_INCORRECT_EMAIL_ENTERED, auditContext, metadataBuilder.build());

        if (hasEnteredIncorrectEmailTooManyTimes(updatedEnterEmailCount)) {
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                    auditContext,
                    ReauthMetadataBuilder.builder(rpPairwiseId)
                            .withAllIncorrectAttemptCounts(updatedCounts)
                            .withFailureReason(ReauthFailureReasons.INCORRECT_EMAIL)
                            .build());

            auditService.submitAuditEvent(
                    AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED,
                    auditContext,
                    pair("attemptNoFailedAt", configurationService.getMaxEmailReAuthRetries()),
                    pairwiseIdMetadataPair);
            throw new AccountLockedException(
                    "Re-authentication is locked due to too many failed attempts.",
                    ErrorResponse.ERROR_1057);
        }

        return generateApiGatewayProxyErrorResponse(404, ERROR_1056);
    }

    private Map<CountType, Integer> incrementEmailCountAndRetrieveNewCounts(
            Optional<Map<CountType, Integer>> maybeExistingCounts, String uniqueUserIdentifier) {
        authenticationAttemptsService.createOrIncrementCount(
                uniqueUserIdentifier,
                NowHelper.nowPlus(
                                configurationService.getReauthEnterEmailCountTTL(),
                                ChronoUnit.SECONDS)
                        .toInstant()
                        .getEpochSecond(),
                JourneyType.REAUTHENTICATION,
                CountType.ENTER_EMAIL);

        Map<CountType, Integer> updatedCounts;
        if (maybeExistingCounts.isPresent()) {
            var existingCounts = new EnumMap<CountType, Integer>(CountType.class);
            existingCounts.putAll(maybeExistingCounts.get());
            var existingEnterEmailCount = existingCounts.getOrDefault(CountType.ENTER_EMAIL, 0);
            // If we already have the counts, we don't have to re-retrieve, we can just increment
            // the map in memory
            existingCounts.put(CountType.ENTER_EMAIL, existingEnterEmailCount + 1);
            updatedCounts = existingCounts;
        } else {
            updatedCounts =
                    authenticationAttemptsService.getCountsByJourney(
                            uniqueUserIdentifier, JourneyType.REAUTHENTICATION);
        }
        return updatedCounts;
    }

    private boolean hasEnteredIncorrectEmailTooManyTimes(int count) {
        var maxRetries = configurationService.getMaxEmailReAuthRetries();

        return count >= maxRetries;
    }
}
