package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.frontendapi.exceptions.AccountLockedException;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.*;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1056;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class CheckReAuthUserHandler extends BaseFrontendHandler<CheckReauthUserRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckReAuthUserHandler.class);

    private final AuditService auditService;
    private final CodeStorageService codeStorageService;

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
                                        userProfile, userContext, request.rpPairwiseId(), input);
                            })
                    .map(rpPairwiseId -> generateSuccessResponse())
                    .orElseGet(() -> generateErrorResponse(request.email(), userContext, input));
        } catch (AccountLockedException e) {
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    request.email(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
            LOG.error("Account is locked due to too many failed attempts.");
            return generateApiGatewayProxyErrorResponse(400, e.getErrorResponse());
        }
    }

    private Optional<String> verifyReAuthentication(
            UserProfile userProfile,
            UserContext userContext,
            String rpPairwiseId,
            APIGatewayProxyRequestEvent input) {
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
                    FrontendAuditableEvent.REAUTHENTICATION_SUCCESSFUL,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    userProfile.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
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
            String email, UserContext userContext, APIGatewayProxyRequestEvent input) {
        if (hasEnteredIncorrectEmailTooManyTimes(email)) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed attempts.", ErrorResponse.ERROR_1057);
        }
        auditService.submitAuditEvent(
                FrontendAuditableEvent.REAUTHENTICATION_INVALID,
                userContext.getClientSessionId(),
                userContext.getSession().getSessionId(),
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN),
                AuditService.UNKNOWN,
                email,
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
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
