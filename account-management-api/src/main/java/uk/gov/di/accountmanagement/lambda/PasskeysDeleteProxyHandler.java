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

public class PasskeysDeleteProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysDeleteProxyHandler.class);
    private final ConfigurationService configurationService;
    private final AccountDataApiService accountDataApiService;

    public PasskeysDeleteProxyHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysDeleteProxyHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accountDataApiService = new AccountDataApiService(configurationService);
    }

    public PasskeysDeleteProxyHandler(
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
                () -> passkeyDeleteProxyHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeyDeleteProxyHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("PasskeysDeleteProxyHandler invoked");

        var publicSubjectId = input.getPathParameters().getOrDefault("publicSubjectId", "");
        var passkeyIdentifier = input.getPathParameters().getOrDefault("passkeyIdentifier", "");
        var token = input.getHeaders().getOrDefault("X-ADAPI-AccessToken", "");

        try {
            var response =
                    accountDataApiService.deletePasskey(publicSubjectId, passkeyIdentifier, token);
            return generateApiGatewayProxyResponse(response.statusCode(), response.body());
        } catch (UnsuccessfulAccountDataApiResponseException e) {
            LOG.warn(
                    "Attempted to delete passkey with ID '{}' but failed due to '{}'",
                    passkeyIdentifier,
                    e.getMessage());
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
    }
}
