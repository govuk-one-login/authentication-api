package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysRetrieveProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysRetrieveProxyHandler.class);
    private final ConfigurationService configurationService;
    private final AccountDataApiService accountDataApiService;

    public PasskeysRetrieveProxyHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysRetrieveProxyHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accountDataApiService = new AccountDataApiService(configurationService);
    }

    public PasskeysRetrieveProxyHandler(
            ConfigurationService configurationService,
            AccountDataApiService accountDataApiService) {
        this.configurationService = configurationService;
        this.accountDataApiService = accountDataApiService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> passkeyRetrieveProxyHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeyRetrieveProxyHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("PasskeysRetrieveProxyHandler invoked");

        var publicSubjectId = input.getPathParameters().getOrDefault("publicSubjectId", "");
        var token = input.getHeaders().getOrDefault("X-ADAPI-AccessToken", "");

        try {
            var response = accountDataApiService.retrievePasskeys(publicSubjectId, token);
            return generateApiGatewayProxyResponse(response.statusCode(), response.body());
        } catch (UnsuccessfulAccountDataApiResponseException e) {
            LOG.warn(
                    "Attempted retrieving passkeys for user but failed due to '{}'",
                    e.getMessage());
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
    }
}
