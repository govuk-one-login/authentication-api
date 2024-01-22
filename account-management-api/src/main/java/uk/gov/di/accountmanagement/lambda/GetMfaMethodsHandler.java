package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.MFAMethodsListResponse;
import uk.gov.di.accountmanagement.entity.MFARecord;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class GetMfaMethodsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(GetMfaMethodsHandler.class);

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);

        LOG.info("GetMFAMethodsHandler received request");

        List<MFARecord> list = new ArrayList<>();

        list.add(new MFARecord("1", "PRIMARY", "test1", "EP", true));
        list.add(new MFARecord("2", "SECONDARY", "test2", "EP", true));

        MFAMethodsListResponse response = new MFAMethodsListResponse(list);
        try {
            return generateApiGatewayProxyResponse(200, objectMapper.writeValueAsString(response));
        } catch (Json.JsonException | IllegalArgumentException ex) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1056);
        }
    }
}
