package uk.gov.di.authentication.interventions.api.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.interventions.api.stub.entity.AccountInterventionsStore;
import uk.gov.di.authentication.interventions.api.stub.entity.InterventionsApiStubResponse;
import uk.gov.di.authentication.interventions.api.stub.services.AccountInterventionsDbService;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AccountInterventionsApiStubHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AccountInterventionsDbService db;
    private final ConfigurationService configurationService;
    private static final Logger LOG =
            LogManager.getLogger(AccountInterventionsApiStubHandler.class);
    private static final String PATH_PARAM_NAME_IN_API_GW = "internalPairwiseId";

    public AccountInterventionsApiStubHandler() {
        this(ConfigurationService.getInstance());
    }

    public AccountInterventionsApiStubHandler(ConfigurationService configurationService) {
        this(new AccountInterventionsDbService(configurationService), configurationService);
    }

    public AccountInterventionsApiStubHandler(
            AccountInterventionsDbService accountInterventionsDbService,
            ConfigurationService configurationService) {
        this.db = accountInterventionsDbService;
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        String internalPairwiseId = input.getPathParameters().get(PATH_PARAM_NAME_IN_API_GW);

        if (configurationService.canLogInternalPairwiseId()) {
            LOG.info(
                    "Received account interventions request with internalPairwiseId {}",
                    internalPairwiseId);
        }

        var maybeAccountInterventionsStore = db.getAccountInterventions(internalPairwiseId);

        try {
            if (maybeAccountInterventionsStore.isPresent()) {
                if (configurationService.canLogInternalPairwiseId()) {
                    LOG.info(
                            "Account Interventions response being generated for internalPairwiseId {}",
                            internalPairwiseId);
                } else {
                    LOG.info("Account Interventions response being generated");
                }
                return generateApiGatewayProxyResponse(
                        200,
                        new InterventionsApiStubResponse(maybeAccountInterventionsStore.get()));
            } else {
                if (configurationService.canLogInternalPairwiseId()) {
                    LOG.info(
                            "No matching account found. Default response sent instead. For internalPairwiseId {}",
                            internalPairwiseId);
                } else {
                    LOG.info("No matching account found. Default response sent instead.");
                }
                AccountInterventionsStore noAccountInterventionStore =
                        new AccountInterventionsStore();
                noAccountInterventionStore
                        .withBlocked(false)
                        .withSuspended(false)
                        .withReproveIdentity(false)
                        .withResetPassword(false);

                return generateApiGatewayProxyResponse(
                        200, new InterventionsApiStubResponse(noAccountInterventionStore));
            }
        } catch (Json.JsonException e) {
            if (configurationService.canLogInternalPairwiseId()) {
                LOG.info(
                        "JSON Exception during Account Interventions check for internalPairwiseId {}",
                        internalPairwiseId);
            }
            return generateApiGatewayProxyResponse(
                    500, "server error - unable to construct response body");
        }
    }
}
