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
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.REAUTHENTICATION_INVALID;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.REAUTHENTICATION_SUCCESSFUL;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1056;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class CheckReAuthUserHandler extends BaseFrontendHandler<CheckReauthUserRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    // INIT PHASE
    private static final Logger LOG = LogManager.getLogger(CheckReAuthUserHandler.class);
    private static RedisConnectionService redis;

    static {
        if (System.getProperty("TEST") == null) {
            redis = new RedisConnectionService(ConfigurationService.getInstance());
        }
    }

    // FUNCTION INIT
    public CheckReAuthUserHandler() {
        this(ConfigurationService.getInstance(), redis);
    }

    public CheckReAuthUserHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(CheckReauthUserRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService, redis);
    }

    // TEST ONLY CONSTRUCTORS
    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CodeStorageService codeStorageService) {
        super(
                CheckReauthUserRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.codeStorageService = codeStorageService;
    }

    public CheckReAuthUserHandler(ConfigurationService configurationService) {
        super(CheckReauthUserRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
    }

    // INVOKE PHASE
    private final AuditService auditService;
    private final CodeStorageService codeStorageService;

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

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        AuditService.UNKNOWN,
                        request.email(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        try {
            return authenticationService
                    .getUserProfileByEmailMaybe(request.email())
                    .flatMap(
                            userProfile -> {
                                if (hasEnteredIncorrectEmailTooManyTimes(userProfile.getEmail())) {
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
                    .orElseGet(() -> generateErrorResponse(request.email(), auditContext));
        } catch (AccountLockedException e) {

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
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
            auditService.submitAuditEvent(REAUTHENTICATION_SUCCESSFUL, auditContext);
            LOG.info("Successfully verified re-authentication");
            removeEmailCountLock(userProfile.getEmail());
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
            String email, AuditContext auditContext) {
        if (hasEnteredIncorrectEmailTooManyTimes(email)) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed attempts.", ErrorResponse.ERROR_1057);
        }
        auditService.submitAuditEvent(REAUTHENTICATION_INVALID, auditContext);
        LOG.info("User not found or no match");
        codeStorageService.increaseIncorrectEmailCount(email);
        return generateApiGatewayProxyErrorResponse(404, ERROR_1056);
    }

    private boolean hasEnteredIncorrectEmailTooManyTimes(String email) {
        var incorrectEmailCount = codeStorageService.getIncorrectEmailCount(email);
        return incorrectEmailCount >= configurationService.getMaxEmailReAuthRetries();
    }

    private boolean hasEnteredIncorrectPasswordTooManyTimes(String email) {
        var incorrectPasswordCount =
                codeStorageService.getIncorrectPasswordCountReauthJourney(email);
        return incorrectPasswordCount >= configurationService.getMaxPasswordRetries();
    }

    private void removeEmailCountLock(String email) {
        var incorrectEmailCount = codeStorageService.getIncorrectEmailCount(email);
        if (incorrectEmailCount != 0) {
            codeStorageService.deleteIncorrectEmailCount(email);
        }
    }
}
