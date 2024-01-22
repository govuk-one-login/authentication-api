package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.DeleteMfaMethodRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class DeleteMfaMethodHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(RetrieveMfaMethodsHandler.class);

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {

            String sessionId =
                    RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
            attachSessionIdToLogs(sessionId);

            String clientId = input.getPathParameters().get("mfaIdentifier");
            var deleteMfaMethod =
                    objectMapper.readValue(input.getBody(), DeleteMfaMethodRequest.class);

            return generateEmptySuccessApiGatewayResponse();
        } catch (Json.JsonException | IllegalArgumentException ex) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1056);
        }
    }
}
