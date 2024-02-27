package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.frontendapi.exceptions.AccountLockedException;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
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

    private final CodeStorageService codeStorageService;

    public CheckReAuthUserHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService) {
        super(
                CheckReauthUserRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
    }

    public CheckReAuthUserHandler(ConfigurationService configurationService) {
        super(CheckReauthUserRequest.class, configurationService);
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
        LOG.info("Processing CheckReAuthUser request for email: {}", request.email());

        try {
            return authenticationService
                    .getUserProfileByEmailMaybe(request.email())
                    .flatMap(
                            userProfile -> {
                                if (isAccountLocked(userProfile.getEmail())) {
                                    throw new AccountLockedException(
                                            "Account is locked due to too many failed attempts.");
                                }

                                return verifyReAuthentication(userProfile, userContext);
                            })
                    .map(rpPairwiseId -> generateSuccessResponse())
                    .orElseGet(() -> generateErrorResponse(request.email()));
        } catch (AccountLockedException e) {
            LOG.error("Account is locked due to too many failed attempts.");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1057);
        }
    }

    private Optional<String> verifyReAuthentication(
            UserProfile userProfile, UserContext userContext) {
        var client = userContext.getClient().orElseThrow();
        var rpPairwiseId =
                ClientSubjectHelper.getSubject(
                                userProfile,
                                client,
                                authenticationService,
                                configurationService.getInternalSectorUri())
                        .getValue();
        LOG.info("rpPairwiseId {}", rpPairwiseId);
        var internalPairwiseId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                userProfile,
                                configurationService.getInternalSectorUri(),
                                authenticationService)
                        .getValue();
        LOG.info("internalPairwiseId {}", rpPairwiseId);
        if (rpPairwiseId.equals(internalPairwiseId)) {
            LOG.info("Successfully verified re-authentication");
            removeEmailCountLock(userProfile.getEmail());
            return Optional.of(rpPairwiseId);
        }

        LOG.info("User re-authentication verification failed");
        return Optional.empty();
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse() {
        LOG.info("Successfully processed CheckReAuthUser request");
        return generateApiGatewayProxyResponse(200, "");
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(String email) {
        LOG.info("User not found or no match");
        codeStorageService.increaseIncorrectEmailCount(email);
        return generateApiGatewayProxyErrorResponse(404, ERROR_1056);
    }

    private boolean isAccountLocked(String email) {
        var incorrectEmailCount = codeStorageService.getIncorrectEmailCount(email);
        return incorrectEmailCount >= configurationService.getMaxEmailReAuthRetries();
    }

    private void removeEmailCountLock(String email) {
        var incorrectEmailCount = codeStorageService.getIncorrectEmailCount(email);
        if (incorrectEmailCount != 0) {
            codeStorageService.deleteIncorrectEmailCount(email);
        }
    }
}
