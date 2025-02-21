package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class MfaMethodsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(MfaMethodsHandler.class);

    public MfaMethodsHandler() {
        this(ConfigurationService.getInstance());
    }

    public MfaMethodsHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> mfaMethodsHandler(input, context));
    }

    public APIGatewayProxyResponseEvent mfaMethodsHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        var subject = input.getPathParameters().get("publicSubjectId");
        if (subject == null || !subject.equals("helloPath")) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        try {
            var mfaMethodCreateRequest =
                    objectMapper.readValue(input.getBody(), MfaMethodCreateRequest.class);

            LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest.mfaMethod());
            return generateApiGatewayProxyResponse(200, input.getBody());
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
