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
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class AccountDeleteProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AccountDeleteProxyHandler.class);
    private final AccountDataApiService accountDataApiService;

    public AccountDeleteProxyHandler() {
        this(ConfigurationService.getInstance());
    }

    public AccountDeleteProxyHandler(ConfigurationService configurationService) {
        this(new AccountDataApiService(configurationService));
    }

    public AccountDeleteProxyHandler(AccountDataApiService accountDataApiService) {
        this.accountDataApiService = accountDataApiService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> accountDeleteProxyHandler(input, context));
    }

    public APIGatewayProxyResponseEvent accountDeleteProxyHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        attachTraceId();
        LOG.info("AccountDeleteProxyHandler called");

        var publicSubjectId = input.getPathParameters().getOrDefault("publicSubjectId", "");
        if (publicSubjectId.isEmpty()) {
            LOG.warn("No publicSubjectId in path parameters, request will likely fail");
        }

        var token = input.getHeaders().getOrDefault("X-ADAPI-AccessToken", "");
        if (token.isEmpty()) {
            LOG.warn("No X-ADAPI-AccessToken in headers, request will likely fail");
        }

        try {
            var response = accountDataApiService.deleteAccount(publicSubjectId, token);
            return generateApiGatewayProxyResponse(response.statusCode(), response.body());
        } catch (UnsuccessfulAccountDataApiResponseException e) {
            LOG.warn("Attempted deleting account but failed due to '{}'", e.getMessage());
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
    }
}
