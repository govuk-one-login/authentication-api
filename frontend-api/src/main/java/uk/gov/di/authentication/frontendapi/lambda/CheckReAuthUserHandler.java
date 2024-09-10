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
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTHENTICATION_INVALID;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTHENTICATION_SUCCESSFUL;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1056;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

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

        try {
            return authenticationService
                    .getUserProfileByEmailMaybe(request.email())
                    .flatMap(
                            userProfile -> {
                                var countTypesToCounts =
                                        authenticationAttemptsService.getCountsByJourney(
                                                userProfile.getSubjectID(),
                                                JourneyType.REAUTHENTICATION);

                                var exceededCountTypes =
                                        ReauthAuthenticationAttemptsHelper
                                                .countTypesWhereUserIsBlockedForReauth(
                                                        countTypesToCounts, configurationService);

                                if (!exceededCountTypes.isEmpty()) {
                                    LOG.info(
                                            "Account is locked due to exceeded counts on count types {}",
                                            exceededCountTypes);
                                    throw new AccountLockedException(
                                            "Account is locked due to too many failed attempts.",
                                            ErrorResponse.ERROR_1057);
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
                                            emailUserIsSignedInWith,
                                            request.rpPairwiseId(),
                                            auditContext));
        } catch (AccountLockedException e) {
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                    auditContext,
                    e.getErrorResponse() == ErrorResponse.ERROR_1045
                            ? AuditService.MetadataPair.pair(
                                    "number_of_attempts_user_allowed_to_login",
                                    configurationService.getMaxPasswordRetries())
                            : AuditService.MetadataPair.pair(
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
        var client = userContext.getClient().orElseThrow();

        var calculatedPairwiseId =
                ClientSubjectHelper.getSubject(
                                userProfile,
                                client,
                                authenticationService,
                                configurationService.getInternalSectorUri())
                        .getValue();

        if (calculatedPairwiseId != null && calculatedPairwiseId.equals(rpPairwiseId)) {
            auditService.submitAuditEvent(AUTH_REAUTHENTICATION_SUCCESSFUL, auditContext);
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
            String emailUserIsSignedInWith, String rpPairwiseId, AuditContext auditContext) {

        String uniqueUserIdentifier;

        if (emailUserIsSignedInWith != null) {
            var userProfile = authenticationService.getUserProfileByEmail(emailUserIsSignedInWith);
            uniqueUserIdentifier = userProfile.getSubjectID();
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

        if (hasEnteredIncorrectEmailTooManyTimes(uniqueUserIdentifier)) {
            throw new AccountLockedException(
                    "Re-authentication is locked due to too many failed attempts.",
                    ErrorResponse.ERROR_1057);
        }

        auditService.submitAuditEvent(AUTH_REAUTHENTICATION_INVALID, auditContext);

        return generateApiGatewayProxyErrorResponse(404, ERROR_1056);
    }

    private boolean hasEnteredIncorrectEmailTooManyTimes(String subjectId) {
        var maxRetries = configurationService.getMaxEmailReAuthRetries();

        var incorrectEmailCount =
                authenticationAttemptsService.getCount(
                        subjectId, JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL);

        return incorrectEmailCount >= maxRetries;
    }
}
