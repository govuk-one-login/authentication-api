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
import uk.gov.di.authentication.frontendapi.exceptions.AccountLockedException;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTHENTICATION_SUCCESSFUL;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1056;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class CheckReAuthUserHandler extends BaseFrontendHandler<CheckReauthUserRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckReAuthUserHandler.class);

    private final AuditService auditService;
    private final CodeStorageService codeStorageService;
    private final AuthenticationAttemptsService authenticationAttemptsService;

    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CodeStorageService codeStorageService,
            AuthenticationAttemptsService authenticationAttemptsService) {
        super(
                CheckReauthUserRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.codeStorageService = codeStorageService;
        this.authenticationAttemptsService = authenticationAttemptsService;
    }

    public CheckReAuthUserHandler(ConfigurationService configurationService) {
        super(CheckReauthUserRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
    }

    public CheckReAuthUserHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(CheckReauthUserRequest.class, configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
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
        LOG.info("Processing CheckReAuthUser request");

        var emailUserIsSignedInWith = userContext.getSession().getEmailAddress();

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        AuditService.UNKNOWN,
                        emailUserIsSignedInWith,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        try {
            return authenticationService
                    .getUserProfileByEmailMaybe(request.email())
                    .flatMap(
                            userProfile -> {
                                if (hasEnteredIncorrectEmailTooManyTimes(userProfile)) {
                                    if (configurationService.supportReauthSignoutEnabled()) {
                                        clearCountOfFailedEmailEntryAttempts(userProfile);
                                    }
                                    throw new AccountLockedException(
                                            "Account is locked due to too many failed attempts.",
                                            ErrorResponse.ERROR_1057);
                                }

                                if (hasEnteredIncorrectPasswordTooManyTimes(
                                        userProfile.getEmail())) {
                                    throw new AccountLockedException(
                                            "Account is locked due to too many failed incorrect password attempts.",
                                            ErrorResponse.ERROR_1045);
                                }

                                return verifyReAuthentication(
                                        userProfile,
                                        userContext,
                                        request.rpPairwiseId(),
                                        auditContext);
                            })
                    .map(rpPairwiseId -> generateSuccessResponse())
                    .orElseGet(
                            () ->
                                    generateErrorResponse(
                                            emailUserIsSignedInWith, auditContext, userContext));
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
            AuditContext auditContext) {
        String calculatedPairwiseId = calculatePairwiseId(userContext, userProfile);

        if (calculatedPairwiseId != null && calculatedPairwiseId.equals(rpPairwiseId)) {
            auditService.submitAuditEvent(AUTH_REAUTHENTICATION_SUCCESSFUL, auditContext);
            LOG.info("Successfully verified re-authentication");
            clearCountOfFailedEmailEntryAttempts(userProfile);
            return Optional.of(rpPairwiseId);
        } else {
            LOG.info("Could not calculate rp pairwise ID");
        }

        LOG.info("User re-authentication verification failed");
        return Optional.empty();
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse() {
        LOG.info("Successfully processed CheckReAuthUser request");
        return generateApiGatewayProxyResponse(200, "");
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            String email, AuditContext auditContext, UserContext userContext) {
        var userProfile = authenticationService.getUserProfileByEmail(email);
        if (hasEnteredIncorrectEmailTooManyTimes(userProfile)) {
            if (configurationService.supportReauthSignoutEnabled()) {
                clearCountOfFailedEmailEntryAttempts(userProfile);
            }
            throw new AccountLockedException(
                    "Account is locked due to too many failed attempts.", ErrorResponse.ERROR_1057);
        }
        LOG.info("User not found or no match");

        int count;

        if (configurationService.isAuthenticationAttemptsServiceEnabled() && userProfile != null) {
            authenticationAttemptsService.createOrIncrementCount(
                    userProfile.getSubjectID(),
                    NowHelper.nowPlus(
                                    configurationService.getReauthEnterEmailCountTTL(),
                                    ChronoUnit.SECONDS)
                            .toInstant()
                            .getEpochSecond(),
                    JourneyType.REAUTHENTICATION,
                    CountType.ENTER_EMAIL);
            count =
                    authenticationAttemptsService.getCount(
                            userProfile.getSubjectID(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_EMAIL);
        } else {
            codeStorageService.increaseIncorrectEmailCount(email);
            count = codeStorageService.getIncorrectEmailCount(email);
        }

        String commonSubjectId =
                userProfile != null
                        ? calculatePairwiseId(userContext, userProfile)
                        : AuditService.UNKNOWN;

        auditService.submitAuditEvent(
                AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                auditContext,
                pair("incorrect_email_attempt_count", count),
                pair("user supplied email address", email),
                pair("common subject identifier", commonSubjectId));

        return generateApiGatewayProxyErrorResponse(404, ERROR_1056);
    }

    private boolean hasEnteredIncorrectEmailTooManyTimes(UserProfile userProfile) {
        if (userProfile == null) return false;
        var maxRetries = configurationService.getMaxEmailReAuthRetries();
        if (configurationService.isAuthenticationAttemptsServiceEnabled()) {
            var incorrectEmailCount =
                    authenticationAttemptsService.getCount(
                            userProfile.getSubjectID(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_EMAIL);
            return incorrectEmailCount >= maxRetries;
        } else {
            var incorrectEmailCount =
                    codeStorageService.getIncorrectEmailCount(userProfile.getEmail());
            return incorrectEmailCount >= maxRetries;
        }
    }

    private boolean hasEnteredIncorrectPasswordTooManyTimes(String email) {
        var incorrectPasswordCount =
                codeStorageService.getIncorrectPasswordCountReauthJourney(email);
        return incorrectPasswordCount >= configurationService.getMaxPasswordRetries();
    }

    private void clearCountOfFailedEmailEntryAttempts(UserProfile userProfile) {
        if (configurationService.isAuthenticationAttemptsServiceEnabled()) {
            authenticationAttemptsService.deleteCount(
                    userProfile.getSubjectID(),
                    JourneyType.REAUTHENTICATION,
                    CountType.ENTER_EMAIL);
        }
        var incorrectEmailCount = codeStorageService.getIncorrectEmailCount(userProfile.getEmail());
        if (incorrectEmailCount != 0) {
            codeStorageService.deleteIncorrectEmailCount(userProfile.getEmail());
        }
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
}
