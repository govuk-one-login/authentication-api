package uk.gov.di.authentication.interventions.api.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.interventions.api.stub.entity.InterventionsApiStubResponse;
import uk.gov.di.authentication.interventions.api.stub.services.AccountInterventionsDbService;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AccountInterventionsApiStubHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AccountInterventionsDbService db;
    private static final String PATH_PARAM_NAME_IN_API_GW = "internalPairwiseId";

    public AccountInterventionsApiStubHandler() {
        this(ConfigurationService.getInstance());
    }

    public AccountInterventionsApiStubHandler(ConfigurationService configurationService) {
        this(new AccountInterventionsDbService(configurationService));
    }

    public AccountInterventionsApiStubHandler(
            AccountInterventionsDbService accountInterventionsDbService) {
        this.db = accountInterventionsDbService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        String internalPairwiseId = input.getPathParameters().get(PATH_PARAM_NAME_IN_API_GW);

        var maybeAccountInterventionsStore = db.getAccountInterventions(internalPairwiseId);

        try {
            if (maybeAccountInterventionsStore.isPresent()) {
                return generateApiGatewayProxyResponse(
                        200,
                        new InterventionsApiStubResponse(maybeAccountInterventionsStore.get()));
            } else {
                return generateApiGatewayProxyResponse(404, "Account not found");
            }
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyResponse(
                    500, "server error - unable to construct response body");
        }
    }
}
