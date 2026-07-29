package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.services.AccountDeleteDynamoService;
import uk.gov.di.authentication.accountdata.services.ConfigurationService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class AccountDeleteHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final String PUBLIC_SUBJECT_ID_KEY = "publicSubjectId";

    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private final AccountDeleteDynamoService accountDeleteDynamoService;

    private static final Logger LOG = LogManager.getLogger(AccountDeleteHandler.class);

    public AccountDeleteHandler(
            ConfigurationService configurationService,
            DynamoService dynamoService,
            AccountDeleteDynamoService accountDeleteDynamoService) {
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
        this.accountDeleteDynamoService = accountDeleteDynamoService;
    }

    public AccountDeleteHandler() {
        this.configurationService = new ConfigurationService();
        this.dynamoService = new DynamoService(configurationService);
        this.accountDeleteDynamoService = new AccountDeleteDynamoService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> accountDeleteHandler(input, context));
    }

    public APIGatewayProxyResponseEvent accountDeleteHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("AccountDeleteHandler called");

        String publicSubjectId = input.getPathParameters().get(PUBLIC_SUBJECT_ID_KEY);

        if (publicSubjectId == null || publicSubjectId.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }

        Optional<UserProfile> maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (maybeUserProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.USER_NOT_FOUND);
        }
        UserProfile userProfile = maybeUserProfile.get();

        try {
            String internalPairwiseSubject =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                    userProfile,
                                    configurationService.getInternalSectorUri(),
                                    dynamoService)
                            .getValue();

            accountDeleteDynamoService.deleteAccount(
                    userProfile.getEmail(), internalPairwiseSubject, publicSubjectId);
        } catch (Exception e) {
            LOG.error("Failed to delete account", e);
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }

        return generateEmptySuccessApiGatewayResponse();
    }
}
