package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class GetMfaMethodsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final ConfigurationService configurationService;

    private static final String PRODUCTION = "production";
    private static final String INTEGRATION = "integration";

    private static final Logger LOG = LogManager.getLogger(GetMfaMethodsHandler.class);

    public GetMfaMethodsHandler() {
        this(ConfigurationService.getInstance());
    }

    public GetMfaMethodsHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent, Context context) {
        addSessionIdToLogs(apiGatewayProxyRequestEvent);

        var disabledEnvironments = List.of(PRODUCTION, INTEGRATION);
        if (disabledEnvironments.contains(configurationService.getEnvironment())) {
            LOG.error(
                    "Request to create MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        return generateApiGatewayProxyResponse(200, "{\"hello\": \"world\"}");
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
    }
}
